const std = @import("std");
const mem = std.mem;
const Io = std.Io;

pub const StartCode3 = enum(u24) {
    // 0x00 0x00 0x01 in little-endian = 0x010000
    valid = 0x010000,
    invalid = 2,
    _,

    pub fn isStartCode(bytes: []const u8) bool {
        if (bytes.len < 3) return false;
        return toStartCode3(bytes[0..3]) == .valid;
    }

    fn toStartCode3(bytes: []const u8) StartCode3 {
        if (bytes.len < 3) return .invalid;
        // Manually construct u24 from 3 bytes (little-endian)
        const value: u24 = @as(u24, bytes[0]) |
            (@as(u24, bytes[1]) << 8) |
            (@as(u24, bytes[2]) << 16);
        return @enumFromInt(value);
    }
};

pub const StartCode4 = enum(u32) {
    // 0x00 0x00 0x00 0x01 in little-endian = 0x01000000
    valid = 0x01000000,
    invalid = 2,
    _,

    pub fn isStartCode4(bytes: []const u8) bool {
        if (bytes.len < 4) return false;
        return toStartCode4(bytes[0..4]) == .valid;
    }

    fn toStartCode4(bytes: []const u8) StartCode4 {
        if (bytes.len < 4) return .invalid;
        // Manually construct u32 from 4 bytes (little-endian)
        const value: u32 = @as(u32, bytes[0]) |
            (@as(u32, bytes[1]) << 8) |
            (@as(u32, bytes[2]) << 16) |
            (@as(u32, bytes[3]) << 24);
        return @enumFromInt(value);
    }
};

pub const Parser = struct {
    source: *Io.Reader,
    position: u64,

    pub fn init(reader: *Io.Reader) Parser {
        return .{
            .source = reader,
            .position = 0,
        };
    }

    pub fn next(self: *Parser) !?Nal {
        try self.skipToStartCode() orelse return null;

        const start_pos = self.position;

        const header_byte = try self.source.takeByte();
        self.position += 1;

        const header = Nal.Header.fromByte(header_byte);

        const end_pos = try self.scanToNextStartCode();

        return Nal.init(header, start_pos, end_pos);
    }

    fn skipToStartCode(self: *Parser) !?void {
        while (true) {
            const peeked = self.source.peek(4) catch |err| switch (err) {
                error.EndOfStream => return null,
                else => return err,
            };

            if (peeked.len >= 4 and StartCode4.isStartCode4(peeked[0..4])) {
                self.source.toss(4);
                self.position += 4;
                return;
            }

            if (peeked.len >= 3 and StartCode3.isStartCode(peeked[0..3])) {
                self.source.toss(3);
                self.position += 3;
                return;
            }

            self.source.toss(1);
            self.position += 1;
        }
    }

    fn scanToNextStartCode(self: *Parser) !u64 {
        var iteration: usize = 0;

        while (true) {
            const peeked = self.source.peekGreedy(4) catch |err| switch (err) {
                error.EndOfStream => {
                    const remaining = self.source.buffered();
                    const end_pos = self.position + remaining.len;
                    self.source.tossBuffered();
                    self.position = end_pos;
                    return end_pos;
                },
                else => return err,
            };

            iteration += 1;

            var i: usize = 0;
            while (i < peeked.len) : (i += 1) {
                if (i + 4 <= peeked.len and StartCode4.isStartCode4(peeked[i .. i + 4])) {
                    const end_pos = self.position + i;
                    self.source.toss(i);
                    self.position = end_pos;
                    return end_pos;
                }

                if (i + 3 <= peeked.len and StartCode3.isStartCode(peeked[i .. i + 3])) {
                    const end_pos = self.position + i;
                    self.source.toss(i);
                    self.position = end_pos;
                    return end_pos;
                }
            }

            const safe_len = if (peeked.len > 3) peeked.len - 3 else 0;
            if (safe_len > 0) {
                self.source.toss(safe_len);
                self.position += safe_len;
            }

            self.source.fillMore() catch |err| switch (err) {
                error.EndOfStream => {
                    // EOS == consume remaining buffered data to close the NAL
                    const remaining = self.source.buffered();
                    const end_pos = self.position + remaining.len;
                    self.source.tossBuffered();
                    self.position = end_pos;
                    return end_pos;
                },
                else => return err,
            };
        }
    }
};

pub const Nal = struct {
    header: Header,
    start_off: u64,
    end_off: u64,

    pub const Header = packed struct(u8) {
        kind: Kind = .unspecified,
        importance: Importance = .disposable,
        forbidden_zero_bit: u1 = 0,

        pub const Importance = enum(u2) {
            disposable = 0,
            low = 1,
            medium = 2,
            higest = 3,
        };

        pub const Kind = enum(u5) {
            unspecified = 0,
            slice_non_idr = 1,
            slice_data_partition_a = 2,
            slice_data_partition_b = 3,
            slice_data_partition_c = 4,
            slice_idr = 5,
            sei = 6,
            sps = 7,
            pps = 8,
            aud = 9,
            end_of_sequence = 10,
            end_of_stream = 11,
            filler_data = 12,
            sps_extension = 13,
            prefix_nal_unit = 14,
            subset_sps = 15,
            depth_parameter_set = 16,
            reserved17 = 17,
            reserved18 = 18,
            slice_auxiliary = 19,
            slice_extension = 20,
            slice_extension_depth = 21,
            reserved22 = 22,
            reserved23 = 23,
            unspecified24 = 24,
            unspecified25 = 25,
            unspecified26 = 26,
            unspecified27 = 27,
            unspecified28 = 28,
            unspecified29 = 29,
            unspecified30 = 30,
            unspecified31 = 31,
        };

        pub const default: Header = .{
            .forbidden_zero_bit = 0,
            .importance = .disposable,
            .kind = .unspecified,
        };

        pub fn init(forbidden_zero_bit: u1, importance: Importance, kind: Kind) Header {
            return .{
                .forbidden_zero_bit = forbidden_zero_bit, // TODO : remember to determine where is best to check for validity,
                .importance = importance, // TODO : check grammar
                .kind = kind,
            };
        }

        pub fn fromByte(byte: u8) Header {
            return std.mem.bytesToValue(Header, &.{byte});
        }

        pub fn toByte(self: *const Header) u8 {
            return std.mem.asBytes(self)[0];
        }
    };

    // start includes the header byte
    pub fn init(header: Header, start: u64, end: u64) Nal {
        return .{
            .header = header,
            .start_off = start,
            .end_off = end,
        };
    }

    pub fn size(self: *const Nal) u64 {
        // love this -| syntaxe
        return self.end_off -| self.start_off;
    }
};

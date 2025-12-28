const std = @import("std");
const mem = std.mem;
const heap = std.heap;
const h264 = @import("h264.zig");
const Io = std.Io;

const RTP_HEADER_SIZE = 12;
const FUA_HEADER_SIZE = 2;
const DEFAULT_MTU = 1200;

pub const Packetizer = struct { // need to find a better name this sucks
    source: *Io.Queue(h264.Nal),
    sequence_number: u16,
    timestamp: u32,
    ssrc: u32,
    current_nal: ?h264.Nal,
    fragment_offset: u32,
    mtu: u32,
    max_payload_size: u32,
    // SPS/PPS caching for periodic resending
    cached_sps: ?h264.Nal,
    cached_pps: ?h264.Nal,
    pending_sps: bool,
    pending_pps: bool,
    packets_since_sps_pps: u32,

    pub fn init(source: *Io.Queue(h264.Nal), ssrc: u32, mtu: u32) Packetizer {
        return .{
            .source = source,
            .sequence_number = 0,
            .timestamp = 0,
            .ssrc = ssrc,
            .current_nal = null,
            .fragment_offset = 0,
            .mtu = mtu,
            .max_payload_size = mtu - RTP_HEADER_SIZE,
            .cached_sps = null,
            .cached_pps = null,
            .pending_sps = false,
            .pending_pps = false,
            .packets_since_sps_pps = 0,
        };
    }

    fn isFragmentationNeeded(self: *const Packetizer, nal: h264.Nal) bool {
        return nal.size() > self.max_payload_size;
    }

    fn incrementTimestamp(self: *Packetizer, delta: u32) void {
        self.timestamp +%= delta;
    }

    pub fn next(self: *Packetizer, io: Io) !?RtpPacket {
        // If we're currently fragmenting a NAL, return the next fragments
        if (self.current_nal) |_| {
            return self.createFragment();
        }

        // If we have pending SPS/PPS to resend, send them first
        if (self.pending_sps) {
            self.pending_sps = false;
            if (self.cached_sps) |sps| {
                std.log.debug("[Stage 2: Packetizer] Resending SPS", .{});
                self.incrementTimestamp(3000);
                self.packets_since_sps_pps = 0; // Reset counter
                if (self.isFragmentationNeeded(sps)) {
                    self.current_nal = sps;
                    self.fragment_offset = 0;
                    return self.createFragment();
                } else {
                    return self.createSinglePacket(sps);
                }
            }
        }

        if (self.pending_pps) {
            self.pending_pps = false;
            if (self.cached_pps) |pps| {
                std.log.debug("[Stage 2: Packetizer] Resending PPS", .{});
                self.incrementTimestamp(3000);
                self.packets_since_sps_pps = 0; // Reset counter
                if (self.isFragmentationNeeded(pps)) {
                    self.current_nal = pps;
                    self.fragment_offset = 0;
                    return self.createFragment();
                } else {
                    return self.createSinglePacket(pps);
                }
            }
        }

        // Otherwise, get the next NAL from the queue
        const nal = self.source.getOne(io) catch |err| {
            std.log.debug("[Stage 2: Packetizer] Source NAL queue returned {s} - no more NALs to process", .{@errorName(err)});
            return null;
        };

        // Log NAL type for debugging
        std.log.debug("[Stage 2: Packetizer] Processing NAL type={s} size={d}", .{ @tagName(nal.header.kind), nal.size() });

        // Cache SPS/PPS for periodic resending
        switch (nal.header.kind) {
            .sps => {
                std.log.debug("[Stage 2: Packetizer] Caching SPS", .{});
                self.cached_sps = nal;
                // Don't reset counter - SPS/PPS in stream don't count as resends
            },
            .pps => {
                std.log.debug("[Stage 2: Packetizer] Caching PPS", .{});
                self.cached_pps = nal;
                // Don't reset counter - SPS/PPS in stream don't count as resends
            },
            .slice_idr => {
                // Before sending IDR, schedule SPS/PPS resend
                std.log.debug("[Stage 2: Packetizer] IDR detected - scheduling SPS/PPS resend", .{});
                self.pending_sps = self.cached_sps != null;
                self.pending_pps = self.cached_pps != null;

                // If we have cached SPS/PPS, return them first (recursively)
                if (self.pending_sps or self.pending_pps) {
                    return self.next(io);
                }
            },
            else => {},
        }

        // Periodically resend SPS/PPS every 100 NALs (for late joiners like FFmpeg)
        self.packets_since_sps_pps += 1;
        if (self.packets_since_sps_pps >= 100) {
            std.log.debug("[Stage 2: Packetizer] Periodic SPS/PPS resend (every 100 NALs)", .{});
            self.pending_sps = self.cached_sps != null;
            self.pending_pps = self.cached_pps != null;

            // If we have cached SPS/PPS, return them first (recursively)
            if (self.pending_sps or self.pending_pps) {
                return self.next(io);
            }
        }

        // Increment timestamp for new NAL
        self.incrementTimestamp(3000); // TODO : need to refine this logic, it's not really correct

        if (self.isFragmentationNeeded(nal)) {
            self.current_nal = nal;
            self.fragment_offset = 0;
            return self.createFragment();
        } else {
            return self.createSinglePacket(nal);
        }
    }

    fn createSinglePacket(self: *Packetizer, nal: h264.Nal) RtpPacket {
        const header = RtpHeader{
            .version = 2,
            .padding = 0,
            .extension = 0,
            .csrc_count = 0,
            .marker = 1, // TODO : make it better no idea right now
            .payload_type = .h264,
            .sequence_number = self.sequence_number,
            .timestamp = self.timestamp,
            .ssrc = self.ssrc,
        };

        self.sequence_number +%= 1; // love this feature

        return RtpPacket{
            .header = header,
            .payload = .{
                .single_nal = SingleNalPayload{
                    .nal_offset = nal.start_off,
                    .nal_len = @intCast(nal.size()),
                },
            },
        };
    }

    fn createFragment(self: *Packetizer) RtpPacket {
        const nal = self.current_nal.?;
        const max_fua_payload = self.mtu - RTP_HEADER_SIZE - FUA_HEADER_SIZE;

        const nal_payload_size = nal.size() - 1; // - header
        const remaining = nal_payload_size - self.fragment_offset;
        const fragment_size = @min(remaining, max_fua_payload);

        const is_first = self.fragment_offset == 0;
        const is_last = (self.fragment_offset + fragment_size) >= nal_payload_size;

        const fua_header = FuAFragment.FuAHeader{
            .forbidden_zero_bit = 0,
            .nal_ref_idc = nal.header.importance,
            .fu_tag = .fua,
            .start = if (is_first) 1 else 0,
            .end = if (is_last) 1 else 0,
            .reserved = 0,
            .original_nal_type = nal.header.kind,
        };

        const rtp_header = RtpHeader{
            .version = 2,
            .padding = 0,
            .extension = 0,
            .csrc_count = 0,
            .marker = if (is_last) 1 else 0,
            .payload_type = .h264,
            .sequence_number = self.sequence_number,
            .timestamp = self.timestamp,
            .ssrc = self.ssrc,
        };

        self.sequence_number +%= 1;

        // Payload offset points into NAL payload (skip NAL header byte)
        const payload_offset = nal.start_off + 1 + self.fragment_offset;

        const packet = RtpPacket{
            .header = rtp_header,
            .payload = .{
                .fua = FuAFragment{
                    .header = fua_header,
                    .payload_offset = payload_offset,
                    .payload_len = @intCast(fragment_size),
                },
            },
        };

        self.fragment_offset += @intCast(fragment_size);

        // If this was the last fragment, clear the current NAL
        if (is_last) {
            self.current_nal = null;
            self.fragment_offset = 0;
        }

        return packet;
    }
};

pub const RtpHeader = packed struct(u96) {
    version: u2 = 2,
    padding: u1 = 0,
    extension: u1 = 0,
    csrc_count: u4 = 0,
    marker: u1 = 0,
    payload_type: PayloadKind = .h264,
    sequence_number: u16,
    timestamp: u32,
    ssrc: u32,

    pub const PayloadKind = enum(u7) {
        h264 = 96,
        _,
    };
};

pub const FuAFragment = struct {
    header: FuAHeader,
    /// Offset into the original NAL payload
    /// (this excludes the original NAL header byte)
    payload_offset: u64,
    /// Length of this fragment’s payload
    payload_len: u32,

    pub const FuAHeader = packed struct(u16) {
        forbidden_zero_bit: u1 = 0,
        nal_ref_idc: h264.Nal.Header.Importance,
        fu_tag: Tag = .fua,
        start: u1,
        end: u1,
        reserved: u1 = 0,
        original_nal_type: h264.Nal.Header.Kind,

        pub const Tag = enum(u5) {
            fua = 28,
        };
    };
};

pub const SingleNalPayload = struct {
    nal_offset: u64, // points to NAL header byte
    nal_len: u32, // header + payload
};

pub const RtpPayload = union(enum) {
    single_nal: SingleNalPayload,
    fua: FuAFragment,
};

pub const RtpPacket = struct {
    header: RtpHeader,
    payload: RtpPayload,

    pub fn payloadSize(self: *const RtpPacket) u32 {
        return switch (self.payload) {
            .single_nal => |p| p.nal_len,
            .fua => |p| p.payload_len + 2, // FU indicator + FU header
        };
    }
};

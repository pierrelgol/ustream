const std = @import("std");
const Io = std.Io;
const Packetizer = @import("Packetizer.zig");
const net = std.Io.net;
const log = std.log;

pub const Server = struct {
    socket: net.Socket,
    dest_addr: net.IpAddress,
    packet_queue: *Io.Queue(Packetizer.RtpPacket),
    file: Io.File,
    file_buffer: []u8,

    pub fn init(
        io: Io,
        dest_addr: net.IpAddress,
        packet_queue: *Io.Queue(Packetizer.RtpPacket),
        file_path: []const u8,
        file_buffer: []u8,
    ) !Server {
        log.debug("[Stage 4: Server] Initializing UDP RTP server", .{});

        // Bind UDP socket (ephemeral port on any interface)
        const bind_addr = try net.IpAddress.parseLiteral("0.0.0.0:0");
        const socket = try bind_addr.bind(io, .{
            .mode = .dgram,
            .protocol = .udp,
        });
        log.debug("[Stage 4: Server] UDP socket bound to ephemeral port", .{});

        // Open separate file descriptor for reading NAL data
        const cwd = Io.Dir.cwd();
        const file = try cwd.openFile(io, file_path, .{ .mode = .read_only });
        log.debug("[Stage 4: Server] Opened file for NAL data reading", .{});

        return .{
            .socket = socket,
            .dest_addr = dest_addr,
            .packet_queue = packet_queue,
            .file = file,
            .file_buffer = file_buffer,
        };
    }

    pub fn run(self: *Server, io: Io) !void {
        log.debug("[Stage 4: Server] Started UDP streaming to {any}", .{self.dest_addr});
        var count: usize = 0;
        var previous_timestamp: ?u32 = null;
        var start_time = try std.time.Instant.now();

        while (true) {
            const packet = self.packet_queue.getOne(io) catch |err| switch (err) {
                error.Canceled, error.Closed => {
                    log.debug("[Stage 4: Server] RTP packet queue closed ({s})", .{@errorName(err)});
                    break;
                },
            };

            // Pace packet delivery based on RTP timestamp
            if (previous_timestamp) |prev_ts| {
                // Calculate timestamp delta (wrapping arithmetic)
                const ts_delta = packet.header.timestamp -% prev_ts;

                // RTP uses 90kHz clock for H.264
                // Convert RTP ticks to nanoseconds: (ticks / 90000) * 1_000_000_000
                if (ts_delta > 0 and ts_delta < 90000) { // Sanity check: less than 1 second
                    const delay_ns: u64 = (@as(u64, ts_delta) * 1_000_000_000) / 90000;

                    // Calculate target time for this packet
                    const current_time = try std.time.Instant.now();
                    const elapsed_ns = current_time.since(start_time);

                    // Sleep if we're ahead of schedule
                    if (delay_ns > elapsed_ns) {
                        const sleep_ns: i96 = @intCast(delay_ns - elapsed_ns);
                        try io.sleep(Io.Duration.fromNanoseconds(sleep_ns), .awake);
                    }

                    start_time = try std.time.Instant.now();
                }
            }

            // Serialize and send packet
            try self.sendPacket(io, packet);
            previous_timestamp = packet.header.timestamp;
            count += 1;

            if (count % 1000 == 0) {
                log.debug("[Stage 4: Server] Sent {d} RTP packets so far", .{count});
            }
        }

        log.debug("[Stage 4: Server] Sent {d} RTP packets total via UDP", .{count});
    }

    fn sendPacket(self: *Server, io: Io, packet: Packetizer.RtpPacket) !void {
        // Allocate buffer for complete UDP packet
        var udp_buffer: [1500]u8 = undefined; // Max Ethernet MTU
        var offset: usize = 0;

        // 1. Serialize RTP header (12 bytes) manually in network byte order (big-endian)
        // Byte 0: V(2) + P(1) + X(1) + CC(4)
        udp_buffer[0] = (@as(u8, packet.header.version) << 6) |
            (@as(u8, packet.header.padding) << 5) |
            (@as(u8, packet.header.extension) << 4) |
            packet.header.csrc_count;

        // Byte 1: M(1) + PT(7)
        udp_buffer[1] = (@as(u8, packet.header.marker) << 7) |
            @as(u8, @intFromEnum(packet.header.payload_type));

        // Bytes 2-3: Sequence number (big-endian)
        std.mem.writeInt(u16, udp_buffer[2..4][0..2], packet.header.sequence_number, .big);

        // Bytes 4-7: Timestamp (big-endian)
        std.mem.writeInt(u32, udp_buffer[4..8][0..4], packet.header.timestamp, .big);

        // Bytes 8-11: SSRC (big-endian)
        std.mem.writeInt(u32, udp_buffer[8..12][0..4], packet.header.ssrc, .big);

        offset = 12;

        // 2. Serialize payload based on type
        var nal_type_byte: u8 = 0;
        switch (packet.payload) {
            .single_nal => |nal| {
                // Read NAL data from file at specified offset
                const nal_data = try self.readFromFile(io, nal.nal_offset, nal.nal_len);
                @memcpy(udp_buffer[offset .. offset + nal_data.len], nal_data);
                offset += nal_data.len;
                if (nal_data.len > 0) nal_type_byte = nal_data[0];

            },
            .fua => |fua| {
                // Serialize FU-A header (2 bytes) manually to avoid padding issues
                // Byte 1: FU indicator = F(1) + NRI(2) + Type(5)
                const fu_indicator: u8 =
                    (@as(u8, fua.header.forbidden_zero_bit) << 7) |
                    (@as(u8, @intFromEnum(fua.header.nal_ref_idc)) << 5) |
                    @as(u8, @intFromEnum(fua.header.fu_tag));

                // Byte 2: FU header = S(1) + E(1) + R(1) + Type(5)
                const fu_header: u8 =
                    (@as(u8, fua.header.start) << 7) |
                    (@as(u8, fua.header.end) << 6) |
                    (@as(u8, fua.header.reserved) << 5) |
                    @as(u8, @intFromEnum(fua.header.original_nal_type));

                udp_buffer[offset] = fu_indicator;
                udp_buffer[offset + 1] = fu_header;
                offset += 2;

                // Read fragment data from file
                const frag_data = try self.readFromFile(io, fua.payload_offset, fua.payload_len);
                @memcpy(udp_buffer[offset .. offset + frag_data.len], frag_data);
                offset += frag_data.len;

                // FU-A type byte is in the header
                nal_type_byte = @as(u8, @intCast(@intFromEnum(fua.header.fu_tag)));
            },
        }

        // Print detailed packet info
        self.printPacketInfo(packet, nal_type_byte, offset);

        // 3. Send UDP packet
        const payload = udp_buffer[0..offset];
        try self.socket.send(io, &self.dest_addr, payload);
    }

    fn printPacketInfo(self: *Server, packet: Packetizer.RtpPacket, nal_type_byte: u8, total_size: usize) void {
        _ = self;

        const stdout = std.fs.File.stdout();
        var buf: [256]u8 = undefined;

        switch (packet.payload) {
            .single_nal => |nal| {
                const nal_kind = nal_type_byte & 0x1F; // Lower 5 bits
                const msg = std.fmt.bufPrint(&buf, "RTP: seq={d:5} ts={d:10} M={d} PT={d:3} SINGLE NAL(type={d:2}) size={d:5}\n", .{
                    packet.header.sequence_number,
                    packet.header.timestamp,
                    packet.header.marker,
                    @intFromEnum(packet.header.payload_type),
                    nal_kind,
                    nal.nal_len,
                }) catch return;
                _ = stdout.write(msg) catch {};
            },
            .fua => |fua| {
                const msg = std.fmt.bufPrint(&buf, "RTP: seq={d:5} ts={d:10} M={d} PT={d:3} FU-A(type={d:2} S={d} E={d}) size={d:5}\n", .{
                    packet.header.sequence_number,
                    packet.header.timestamp,
                    packet.header.marker,
                    @intFromEnum(packet.header.payload_type),
                    @intFromEnum(fua.header.original_nal_type),
                    fua.header.start,
                    fua.header.end,
                    total_size,
                }) catch return;
                _ = stdout.write(msg) catch {};
            },
        }
    }

    fn readFromFile(self: *Server, io: Io, file_offset: u64, length: u32) ![]const u8 {
        // Read data at specific position using positional read (thread-safe, doesn't affect seek position)
        const buffer_slice = self.file_buffer[0..length];
        var buffers = [_][]u8{buffer_slice};
        const bytes_read = try self.file.readPositional(io, &buffers, file_offset);
        return self.file_buffer[0..bytes_read];
    }

    pub fn deinit(self: *Server, io: Io) void {
        log.debug("[Stage 4: Server] Cleaning up resources", .{});
        self.socket.close(io);
        self.file.close(io);
    }
};

pub fn generateSdpFile(file_path: []const u8) !void {
    log.debug("[Pipeline] Generating SDP file: {s}", .{file_path});

    const sdp_content =
        \\v=0
        \\o=- 0 0 IN IP4 127.0.0.1
        \\s=H264 RTP stream
        \\c=IN IP4 127.0.0.1
        \\t=0 0
        \\m=video 5004 RTP/AVP 96
        \\a=rtpmap:96 H264/90000
        \\
    ;

    const file = try std.fs.cwd().createFile(file_path, .{});
    defer file.close();
    try file.writeAll(sdp_content);

    log.debug("[Pipeline] SDP file generated successfully", .{});
}

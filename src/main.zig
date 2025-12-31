const std = @import("std");
const heap = std.heap;
const mem = std.mem;
const log = std.log;
const process = std.process;
const Io = std.Io;
const h264 = @import("h264.zig");
const time = std.time;
const Packetizer = @import("Packetizer.zig");
const Server = @import("server.zig");

fn produceNal(io: Io, parser: *h264.Parser, queue: *Io.Queue(h264.Nal)) !void {
    log.debug("[Stage 1: Producer] Started NAL production", .{});
    var count: usize = 0;

    while (try parser.next()) |nal| {
        try queue.putOne(io, nal);
        count += 1;
        if (count % 100 == 0) {
            log.debug("[Stage 1: Producer] Produced {d} NALs so far", .{count});
        }
    }

    log.debug("[Stage 1: Producer] Finished parsing - produced {d} NAL units total", .{count});
    log.debug("[Stage 1: Producer] Closing NAL queue (consumers can still drain remaining items)", .{});
    queue.close(io);

    log.info("Total Nal packets produced: {}", .{count});
    log.debug("[Stage 1: Producer] Exited", .{});
}

fn consumeNalProducePacket(io: Io, packetizer: *Packetizer.Packetizer, queue: *Io.Queue(Packetizer.RtpPacket)) !void {
    log.debug("[Stage 2: Packetizer] Started consuming NALs and producing RTP packets", .{});
    var nal_count: usize = 0;
    var packet_count: usize = 0;

    while (try packetizer.next(io)) |packet| {
        try queue.putOne(io, packet);
        packet_count += 1;

        if (packet.header.marker == 1) {
            nal_count += 1;
            if (nal_count % 100 == 0) {
                log.debug("[Stage 2: Packetizer] Processed {d} NALs -> {d} RTP packets so far", .{ nal_count, packet_count });
            }
        }
    }

    log.debug("[Stage 2: Packetizer] NAL queue closed and drained - consumed {d} NALs total", .{nal_count});
    log.debug("[Stage 2: Packetizer] Produced {d} RTP packets total", .{packet_count});
    log.debug("[Stage 2: Packetizer] Closing RTP packet queue (consumer can still drain remaining items)", .{});
    queue.close(io);

    log.info("Total RTP packets produced: {}", .{packet_count});
    log.debug("[Stage 2: Packetizer] Exited", .{});
}

pub fn main() !void {
    const gpa = heap.smp_allocator;

    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();

    const argv: [][:0]u8 = process.argsAlloc(gpa) catch |err| {
        return log.err("Fatal : {}", .{err});
    };
    defer process.argsFree(gpa, argv);

    if (argv.len < 2) {
        return log.err("Usage: {s} <input.h264> [fps]", .{argv[0]});
    }

    const fps: u32 = if (argv.len > 2)
        std.fmt.parseInt(u32, argv[2], 10) catch |err| {
            return log.err("Fatal: invalid fps '{s}': {s}", .{ argv[2], @errorName(err) });
        }
    else
        30;
    if (fps == 0) {
        return log.err("Fatal: fps must be > 0", .{});
    }
    const timestamp_step: u32 = 90000 / fps;
    if (timestamp_step == 0) {
        return log.err("Fatal: fps too high for 90kHz clock", .{});
    }

    const cwd = std.Io.Dir.cwd();
    const file = cwd.openFile(threaded.io(), argv[1], .{ .mode = .read_only }) catch |err| {
        return log.err("Fatal : {}", .{err});
    };
    defer file.close(threaded.io());

    var file_buffer: [256 * 1024]u8 = undefined;
    var file_reader = file.reader(threaded.io(), &file_buffer);
    const reader = &file_reader.interface;

    var parser = h264.Parser.init(reader);
    var nal_buffer: [1024]h264.Nal = undefined;
    var nal_queue: Io.Queue(h264.Nal) = .init(&nal_buffer);

    var timer = try time.Timer.start();

    var pak_buffer: [1024]Packetizer.RtpPacket = undefined;
    var pak_queue: Io.Queue(Packetizer.RtpPacket) = .init(&pak_buffer);
    var packetizer = Packetizer.Packetizer.init(&nal_queue, 421412, 1500, timestamp_step);

    var server_file_buffer: [256 * 1024]u8 = undefined;
    const dest_host = "127.0.0.1";
    const dest_port: u16 = 5004;
    const dest_addr = try std.Io.net.IpAddress.parseLiteral("127.0.0.1:5004");

    var server = try Server.Server.init(
        threaded.io(),
        dest_addr,
        &pak_queue,
        argv[1],
        &server_file_buffer,
    );
    defer server.deinit(threaded.io());

    const sdp_data = try Io.Dir.cwd().readFileAlloc(
        threaded.io(),
        argv[1],
        gpa,
        std.Io.Limit.limited(64 * 1024 * 1024),
    );
    defer gpa.free(sdp_data);
    const sps_pps = Server.findSpsPps(sdp_data);
    try Server.generateSdpFile(
        gpa,
        threaded.io(),
        "session.sdp",
        dest_host,
        dest_port,
        sps_pps,
    );

    log.debug("[Pipeline] Launching 4-stage concurrent pipeline", .{});
    log.debug("[Pipeline] - Stage 1: NAL Producer (H.264 parser)", .{});
    log.debug("[Pipeline] - Stage 2: RTP Packetizer (NAL -> RTP packets)", .{});
    log.debug("[Pipeline] - Stage 3: (removed - was dummy consumer)", .{});
    log.debug("[Pipeline] - Stage 4: UDP RTP Server (stream to VLC)", .{});
    log.debug("[Pipeline] Target: {any}", .{dest_addr});

    var f1 = try threaded.io().concurrent(produceNal, .{ threaded.io(), &parser, &nal_queue });
    errdefer f1.cancel(threaded.io()) catch {};

    var f2 = try threaded.io().concurrent(consumeNalProducePacket, .{ threaded.io(), &packetizer, &pak_queue });
    errdefer f2.cancel(threaded.io()) catch {};

    var f4 = try threaded.io().concurrent(Server.Server.run, .{ &server, threaded.io() });
    errdefer f4.cancel(threaded.io()) catch {};

    log.debug("[Pipeline] All stages started, waiting for completion...", .{});

    f1.await(threaded.io()) catch |err| switch (err) {
        error.Closed, error.Canceled => {},
        else => return err,
    };
    log.debug("[Pipeline] Stage 1 (Producer) completed", .{});

    f2.await(threaded.io()) catch |err| switch (err) {
        error.Closed, error.Canceled => {},
        else => return err,
    };
    log.debug("[Pipeline] Stage 2 (Packetizer) completed", .{});

    try f4.await(threaded.io());
    log.debug("[Pipeline] Stage 4 (UDP Server) completed", .{});

    const elapsed_ns = timer.lap();
    const elapsed_ms = elapsed_ns / time.ns_per_ms;

    log.debug("[Pipeline] All stages completed successfully in {d}ms", .{elapsed_ms});
    log.info("\nProcessing completed in {}ms\n", .{elapsed_ms});
}

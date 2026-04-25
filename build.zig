const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const root_module = b.createModule(.{
        .root_source_file = b.path("src/ffi.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Zig module for package manager consumers
    _ = b.addModule("zig-crypto", .{
        .root_source_file = b.path("src/ffi.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Static library for C FFI consumers
    const lib = b.addLibrary(.{
        .name = "zig-crypto",
        .root_module = root_module,
        .linkage = .static,
    });

    b.installArtifact(lib);

    // Documentation generation
    const docs_step = b.step("docs", "Generate API documentation");
    const docs_lib = b.addLibrary(.{
        .name = "zig-crypto",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/ffi.zig"),
            .target = target,
            .optimize = optimize,
        }),
        .linkage = .static,
    });
    const install_docs = b.addInstallDirectory(.{
        .source_dir = docs_lib.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "docs",
    });
    docs_step.dependOn(&install_docs.step);

    // Unit tests
    const test_step = b.step("test", "Run unit tests");

    inline for (.{
        "src/sha256.zig",
        "src/hmac.zig",
        "src/aes.zig",
        "src/pbkdf2.zig",
        "src/random.zig",
        "src/ecdh.zig",
        "src/ed25519.zig",
    }) |test_file| {
        const t = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path(test_file),
                .target = target,
                .optimize = optimize,
            }),
        });
        test_step.dependOn(&b.addRunArtifact(t).step);
    }

    // Property-based tests
    const pbt_step = b.step("test-pbt", "Run property-based tests");

    inline for (.{
        .{ .file = "tests/pbt_sha256.zig", .mod = "sha256" },
        .{ .file = "tests/pbt_aes.zig", .mod = "aes" },
        .{ .file = "tests/pbt_ecdh.zig", .mod = "ecdh" },
        .{ .file = "tests/pbt_ed25519.zig", .mod = "ed25519" },
    }) |entry| {
        const t = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path(entry.file),
                .target = target,
                .optimize = optimize,

                .imports = &.{
                    .{ .name = entry.mod, .module = b.createModule(.{
                        .root_source_file = b.path("src/" ++ entry.mod ++ ".zig"),
                        .target = target,
                        .optimize = optimize,
                    }) },
                },
            }),
        });
        pbt_step.dependOn(&b.addRunArtifact(t).step);
    }
}

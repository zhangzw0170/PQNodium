#!/usr/bin/env pwsh
# PQNodium - build.ps1
# Release build.

param(
    [switch]$Release,
    [string]$Target
)

$cargo_args = @("build", "-p", "pqnodium-cli")
if ($Release) { $cargo_args += "--release" }
if ($Target) { $cargo_args += "--target", $Target }

& cargo @cargo_args

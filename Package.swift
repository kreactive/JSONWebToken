// swift-tools-version:4.0

import PackageDescription

let pkg = Package(name: "JSONWebToken")
pkg.products = [
    .library(name: "JSONWebToken", targets: ["JSONWebToken"]),
]
pkg.platforms = [
    .iOS(.v11),
]

let pmk: Target = .target(name: "JSONWebToken")
pmk.path = "JSONWebToken"
pkg.swiftLanguageVersions = [5]
pkg.targets = [
    pmk,
    .testTarget(name: "JSONWebTokenTests", dependencies: ["JSONWebToken"], path: "JSONWebTokenTests"),
]

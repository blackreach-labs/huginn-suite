# Technical Design Specification: Individual File Auto-Update & Licensing System
**Domain:** blackreachlabs.com  
**Infrastructure Stack:** AWS S3, AWS CloudFront, AWS Route 53  
**Client Stack:** Python Desktop Application (Distributed as loose, raw `.py` files)  
**Workflow Paradigm:** Kiro Tech-Design-First Spec

---

## 1. System Architecture Overview

This specification establishes an unauthenticated, highly scalable, and rate-limit-resistant update mechanism for the Blackreach Labs Python desktop application. Because the application is distributed as a collection of individual source files without compression, updates are fetched file-by-file based on cryptographic differences. The system isolates the update payload from the GitHub API by utilizing Amazon S3 as an immutable file store and CloudFront as an edge-cached Content Delivery Network (CDN).

### 1.1 Infrastructure Components
* **Primary Domain:** `blackreachlabs.com`
* **Update Endpoint:** `https://blackreachlabs.com`
* **Storage Layer:** AWS S3 Bucket (`blackreach-labs-app-releases`)
* **Distribution Layer:** AWS CloudFront CDN mapped via AWS Route 53 (ALIAS record)

```text
[ Running Python App ]
│
├── (1) HTTPS GET /dist/manifest.json ────> [ CloudFront Edge Cache ]
││ (Cache Miss)
│▼
└── (2) HTTPS GET /src/[module_files].py <── [ S3 Bucket Resource ]
```

---

## 2. Infrastructure Specification (AWS Platform)

Kiro Agent Instructions: Use the following structural guidelines to generate AWS CloudFormation or Terraform resource configurations.

### 2.1 S3 Bucket Layout
The bucket `blackreach-labs-app-releases` must maintain a strict, predictable prefix structure holding the manifest and the raw source files:
```text
blackreach-labs-app-releases/
├── dist/
│   └── manifest.json                # Single source-of-truth metadata and file map
└── src/                             # Raw Python files matching the app's file tree
    ├── main.py
    ├── config.py
    └── utils/
        └── helpers.py
```

### 2.2 S3 Bucket Policy & Security
* **Public Access Block:** Enabled (All public access blocked at the bucket level).
* **Access Control:** Origin Access Control (OAC) must be configured to allow *only* the CloudFront distribution read access to the bucket objects (`s3:GetObject`).

### 2.3 CloudFront CDN Configuration
* **Origin:** `://amazonaws.com`
* **Alternate Domain Name (CNAME):** `updates.blackreachlabs.com`
* **Cache Policy (manifest.json):** Create a specific cache behavior for `/dist/manifest.json` with a Low Time-To-Live (TTL = 300 seconds) to ensure rapid propagation of new updates.
* **Cache Policy (src/*):** Default cloud caching behaviors apply. To invalidate files immediately upon new deploys without waiting for TTLs, Kiro must include an AWS CLI invalidation script (`aws cloudfront create-invalidation`) for deployment workflows.

---

## 3. Data Contract: Update Manifest (`manifest.json`)

This file is hosted at `https://blackreachlabs.com`. Instead of global version strings, it explicitly tracks individual file hashes.

```json
{
  "latest_version": "1.1.0",
  "release_date": "2026-06-17T00:00:00Z",
  "files": [
    {
      "path": "main.py",
      "url": "https://blackreachlabs.com",
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    },
    {
      "path": "config.py",
      "url": "https://blackreachlabs.com",
      "sha256": "4fa52199b50e331b6727293b6e8284612e3e5bc87b5a83709b4d8234a9b6c00d"
    },
    {
      "path": "utils/helpers.py",
      "url": "https://blackreachlabs.com",
      "sha256": "8f4345afb25a3a2d2188432a673a6b5a321949cf9b6bb9319e59dca43b1a8d01"
    }
  ],
  "release_notes": "Incremental source file update infrastructure synced directly with AWS CloudFront."
}
```

---

## 4. Client Implementation Specification (Python Application)

Kiro Agent Instructions: Write the Python client update module complying with the following programmatic constraints and lifecycle phases.

### 4.1 Dependency Restrictions
* Use standard library components exclusively (`urllib.request`, `json`, `os`, `sys`, `hashlib`, `pathlib`).
* No external networking or zip processing utilities are permitted.

### 4.2 Application Lifecycle Update Logic
The updater module must expose a function/class `ManifestUpdater` containing the following processing steps:

1. **Phase 1: Fetch Manifest**
   * Send an unauthenticated `GET` request to `https://blackreachlabs.com`.
   * Parse the root structure to check global `latest_version` against local version state.

2. **Phase 2: Differential File Verification Loop**
   * If an update is required, loop through every item defined in the `files` array.
   * For each file path, check if the local file exists on disk.
   * If the local file exists, compute its local SHA-256 hash. Compare it against the manifest `sha256` value.
   * If the local file does not exist, or the hashes do not match, mark that file for downloading.

3. **Phase 3: Safe File Overwrite**
   * Because Python loads scripts into memory upon initial execution, the interpreter does not lock active `.py` files on disk (unlike binary `.exe` blocks).
   * Stream files marked for downloading directly from their CloudFront `url`.
   * Ensure missing parent sub-directories are dynamically generated via `pathlib.Path.mkdir(parents=True, exist_ok=True)`.
   * Overwrite the local files directly with the downloaded stream.

4. **Phase 4: Clean Script Hot-Reload**
   * Once all mismatched or missing files are updated, trigger a clean application state clear.
   * Use `os.execv(sys.executable, [sys.executable] + sys.argv)` to smoothly discard old memory allocations and completely reload the updated source files into the runtime interpreter.

---

## 5. Licensing System Hook Requirement

When implementing code generation for the licence verification routine:
* Design the `Check for Updates` execution layer so it can accept an optional argument `license_key`.
* **Future-proofing Hook:** Provide a clear abstraction interface where this direct `GET` to CloudFront can be swapped later for a secure `POST` request to `https://blackreachlabs.com` to conditionally provision signed S3 object keys only to valid license holders.

---

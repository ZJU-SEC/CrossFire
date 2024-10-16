## Introduction

This is a kernel extension interface for managing traces.

To set the trace, follow these steps:

- Set the kext name for `struct ctl_info info.ctl_name`.
- Connect to the kext through `ioctl` and `connect` to obtain the `ctl_id`.
- Set the trace using `ioctl` with the `ctl_id`.
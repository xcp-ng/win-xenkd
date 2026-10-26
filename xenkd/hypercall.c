/* Copyright (c) Xen Project.
 * Copyright (c) Cloud Software Group, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms,
 * with or without modification, are permitted provided
 * that the following conditions are met:
 *
 * *   Redistributions of source code must retain the above
 *     copyright notice, this list of conditions and the
 *     following disclaimer.
 * *   Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the
 *     following disclaimer in the documentation and/or other
 *     materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

// Adapted from xencrsh's hypercall_stub.c and hvm.c/evtchn.c. Hypercalls are issued directly with
// VMCALL/VMMCALL instead of through a hypercall page, so no guest memory has to be set up beforehand.

#include <intrin.h>

#include "hypercall.h"

typedef enum _HYPERCALL_INSTRUCTION {
    HYPERCALL_INSTRUCTION_UNKNOWN,
    HYPERCALL_INSTRUCTION_VMCALL,
    HYPERCALL_INSTRUCTION_VMMCALL,
} HYPERCALL_INSTRUCTION;

typedef struct _CPU_VENDOR_DATA {
    ULONG EBX;
    ULONG ECX;
    ULONG EDX;
    HYPERCALL_INSTRUCTION Instruction;
} CPU_VENDOR_DATA;

static const CPU_VENDOR_DATA HypercallVendorData[] = {
    // Note that the vendor data goes EBX-ECX-EDX
    // "GenuineIntel"
    {0x756E6547, 0x6C65746E, 0x49656E69, HYPERCALL_INSTRUCTION_VMCALL},
    // "AuthenticAMD"
    {0x68747541, 0x444D4163, 0x69746E65, HYPERCALL_INSTRUCTION_VMMCALL},
    // "CentaurHauls"
    {0x746E6543, 0x736C7561, 0x48727561, HYPERCALL_INSTRUCTION_VMCALL},
    // "  Shanghai  "
    {0x68532020, 0x20206961, 0x68676E61, HYPERCALL_INSTRUCTION_VMCALL},
    // "HygonGenuine"
    {0x6F677948, 0x656E6975, 0x6E65476E, HYPERCALL_INSTRUCTION_VMMCALL},
};

// "XenVMMXenVMM"
#define XEN_SIGNATURE_EBX 0x566E6558
#define XEN_SIGNATURE_ECX 0x65584D4D
#define XEN_SIGNATURE_EDX 0x4D4D566E

static HYPERCALL_INSTRUCTION HypercallInstruction = HYPERCALL_INSTRUCTION_UNKNOWN;

NTSTATUS
HypercallInitialize(VOID) {
    ULONG XenBaseLeaf;
    int Value[4];
    HYPERCALL_INSTRUCTION Instruction;
    ULONG Index;

    // Don't use strcmp here: extensibility modules can't have any imports.
    for (XenBaseLeaf = 0x40000000; XenBaseLeaf <= 0x40000100; XenBaseLeaf += 0x100) {
        __cpuid(Value, XenBaseLeaf);
        if ((ULONG)Value[1] == XEN_SIGNATURE_EBX && (ULONG)Value[2] == XEN_SIGNATURE_ECX &&
            (ULONG)Value[3] == XEN_SIGNATURE_EDX && (ULONG)Value[0] >= XenBaseLeaf + 2)
            break;
    }
    if (XenBaseLeaf > 0x40000100)
        return STATUS_NOT_SUPPORTED;

    Instruction = HYPERCALL_INSTRUCTION_UNKNOWN;
    __cpuid(Value, 0);
    for (Index = 0; Index < ARRAYSIZE(HypercallVendorData); Index++) {
        const CPU_VENDOR_DATA *CurrentData = &HypercallVendorData[Index];

        if ((ULONG)Value[1] == CurrentData->EBX && (ULONG)Value[2] == CurrentData->ECX &&
            (ULONG)Value[3] == CurrentData->EDX) {
            Instruction = CurrentData->Instruction;
            break;
        }
    }
    if (Instruction == HYPERCALL_INSTRUCTION_UNKNOWN)
        return STATUS_NOT_SUPPORTED;

    HypercallInstruction = Instruction;
    return STATUS_SUCCESS;
}

extern uintptr_t __stdcall hypercall2_vmcall(_In_ uint32_t ord, _In_ uintptr_t arg1, _In_ uintptr_t arg2);
extern uintptr_t __stdcall hypercall2_vmmcall(_In_ uint32_t ord, _In_ uintptr_t arg1, _In_ uintptr_t arg2);

ULONG_PTR
___Hypercall2(_In_ ULONG Ordinal, _In_ ULONG_PTR Argument1, _In_ ULONG_PTR Argument2) {
    switch (HypercallInstruction) {
    case HYPERCALL_INSTRUCTION_VMCALL:
        return hypercall2_vmcall(Ordinal, Argument1, Argument2);
    case HYPERCALL_INSTRUCTION_VMMCALL:
        return hypercall2_vmmcall(Ordinal, Argument1, Argument2);
    default:
        return (ULONG_PTR)-XEN_ENOSYS;
    }
}

NTSTATUS
HvmGetParameter(_In_ ULONG Param, _Out_ PULONGLONG Value) {
    struct xen_hvm_param op;
    LONG_PTR rc;

    op.domid = DOMID_SELF;
    op.index = Param;
    op.value = 0;

    rc = Hypercall2(LONG_PTR, hvm_op, HVMOP_get_param, &op);
    if (rc < 0)
        return STATUS_UNSUCCESSFUL;

    *Value = op.value;
    return STATUS_SUCCESS;
}

NTSTATUS
EventChannelSend(_In_ ULONG LocalPort) {
    struct evtchn_send op;
    LONG_PTR rc;

    op.port = LocalPort;

    rc = Hypercall2(LONG_PTR, event_channel_op, EVTCHNOP_send, &op);
    if (rc < 0)
        return STATUS_UNSUCCESSFUL;

    return STATUS_SUCCESS;
}

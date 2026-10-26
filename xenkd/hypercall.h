#pragma once

#include "xenkd.h"

NTSTATUS
HypercallInitialize(VOID);

ULONG_PTR
___Hypercall2(_In_ ULONG Ordinal, _In_ ULONG_PTR Argument1, _In_ ULONG_PTR Argument2);

#define Hypercall2(_Type, _Name, _Argument1, _Argument2) \
    ((_Type)___Hypercall2(__HYPERVISOR_##_Name, (ULONG_PTR)(_Argument1), (ULONG_PTR)(_Argument2)))

NTSTATUS
HvmGetParameter(_In_ ULONG Param, _Out_ PULONGLONG Value);

NTSTATUS
EventChannelSend(_In_ ULONG LocalPort);

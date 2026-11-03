/*
 * mfstub.h — Media Foundation 最小声明子集（仅用于非 Windows 平台的离线
 * 语法/类型自检，见 check.sh）。Windows 目标机构建**不使用本文件**（见
 * yuduan_enc_mf.c 的 #ifdef _WIN32 分支，直接用 SDK 头 <mfapi.h> 等）。
 *
 * GUID 值与接口方法顺序来自 MSDN（IMFTransform/IMFSample/ICodecAPI）；
 * 本文件只保证自检的自洽性，运行时 ABI 由 Windows SDK 头保证。
 */
#pragma once

#include <stdint.h>
#include <stddef.h>

typedef int32_t HRESULT;
typedef uint32_t UINT32;
typedef uint64_t UINT64;
typedef long LONG;
typedef unsigned int DWORD;
typedef unsigned short WORD;
typedef unsigned char BYTE;
typedef int BOOL;
typedef size_t SIZE_T;
typedef void *LPVOID;
typedef const char *LPCSTR;
typedef wchar_t WCHAR;
typedef const wchar_t *LPCWSTR;
#define S_OK ((HRESULT)0)
#define S_FALSE ((HRESULT)1)
#define E_FAIL ((HRESULT)0x80004005)
#define E_OUTOFMEMORY ((HRESULT)0x8007000E)
#define E_NOTIMPL ((HRESULT)0x80004001)
#define MF_E_TRANSFORM_NEED_MORE_INPUT ((HRESULT)0xC00D6D72)
#define MF_E_TRANSFORM_TYPE_NOT_SET ((HRESULT)0xC00D6D78)
#define MF_E_NO_MORE_TYPES ((HRESULT)0xC00D36B9)
#define SUCCEEDED(hr) ((HRESULT)(hr) >= 0)
#define FAILED(hr) ((HRESULT)(hr) < 0)
#define STDMETHODCALLTYPE

typedef struct _GUID { uint32_t Data1; uint16_t Data2, Data3; uint8_t Data4[8]; } GUID;
typedef GUID IID;
#define DEFINE_GUID(n, a, b, c, d0, d1, d2, d3, d4, d5, d6, d7) \
    static const GUID n = { a, b, c, { d0, d1, d2, d3, d4, d5, d6, d7 } }

DEFINE_GUID(IID_IMFTransform, 0xbf94c763, 0x3e41, 0x42e4, 0x89, 0x99, 0x31, 0xdc, 0x5c, 0x32, 0x31, 0x33);
DEFINE_GUID(IID_IMFAttributes, 0x2cd2d921, 0xc447, 0x44a7, 0xa1, 0x3c, 0x4a, 0xda, 0xbf, 0xc2, 0x47, 0xe3);
DEFINE_GUID(IID_IMFMediaType, 0x44ae0fa8, 0xea31, 0x4109, 0x8d, 0x2e, 0x4f, 0x4a, 0x7b, 0x54, 0xe6, 0x75);
DEFINE_GUID(IID_IMFSample, 0x314f6c55, 0x233c, 0x4b40, 0xae, 0xc1, 0x4d, 0x0a, 0xbc, 0x40, 0xe6, 0x65);
DEFINE_GUID(IID_IMFMediaBuffer, 0x045fa563, 0x4d9c, 0x4d10, 0xba, 0xb4, 0x31, 0xb0, 0xe6, 0xe4, 0xdc, 0x62);
DEFINE_GUID(IID_ICodecAPI, 0x901db4c7, 0x31ce, 0x41a2, 0x85, 0xdc, 0x8f, 0xa0, 0xbf, 0x41, 0xb8, 0xda);
DEFINE_GUID(MFMediaType_Video, 0x73646976, 0x0000, 0x0010, 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71);
DEFINE_GUID(MFVideoFormat_NV12, 0x3231564e, 0x0000, 0x0010, 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71);
DEFINE_GUID(MFVideoFormat_H264, 0x34363248, 0x0000, 0x0010, 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71);
DEFINE_GUID(MF_MT_MAJOR_TYPE, 0x48eba18e, 0xf8c9, 0x4687, 0xbf, 0x11, 0x0a, 0x74, 0xc9, 0xf9, 0x6a, 0x8f);
DEFINE_GUID(MF_MT_SUBTYPE, 0xf7e34c9a, 0x42e8, 0x4714, 0xb7, 0x4b, 0xcb, 0x29, 0xd7, 0x2c, 0x35, 0xe5);
DEFINE_GUID(MF_MT_FRAME_SIZE, 0x1652c33d, 0x86b4, 0x43f4, 0x83, 0xe6, 0xa2, 0x59, 0xca, 0xaa, 0xf0, 0x8a);
DEFINE_GUID(MF_MT_FRAME_RATE, 0xc459a2e8, 0x3d2c, 0x4e44, 0xb1, 0x32, 0xff, 0xc5, 0xfa, 0x53, 0x8f, 0xc5);
DEFINE_GUID(MF_MT_AVG_BITRATE, 0x20332624, 0xfb0d, 0x4d9e, 0xbd, 0x0d, 0xcb, 0xf6, 0x78, 0x6c, 0x10, 0x2e);
DEFINE_GUID(MF_MT_MPEG2_PROFILE, 0xad76a80b, 0x2d5c, 0x4e0b, 0xb3, 0x75, 0x64, 0xe5, 0x20, 0x13, 0x70, 0x36);
DEFINE_GUID(MF_MT_INTERLACE_MODE, 0xe2724bb8, 0xe676, 0x4806, 0xb4, 0xb2, 0xa8, 0xd6, 0xef, 0xb4, 0x4c, 0xcd);
DEFINE_GUID(MF_MT_ALL_SAMPLES_INDEPENDENT, 0xc9173739, 0x5e56, 0x461c, 0xb7, 0x13, 0x46, 0xfb, 0x99, 0x5c, 0xb9, 0x5f);
DEFINE_GUID(MF_MT_FIXED_SIZE_SAMPLES, 0xb8ebef80, 0xb73f, 0x4a3d, 0x96, 0xca, 0x52, 0xee, 0xc7, 0x48, 0x09, 0x67);
DEFINE_GUID(MFT_CATEGORY_VIDEO_ENCODER, 0xf79eac7d, 0xe545, 0x4387, 0xbd, 0xee, 0xd6, 0x47, 0xd7, 0xbd, 0xe4, 0x2a);
DEFINE_GUID(CODECAPI_AVEncVideoForceKeyFrame, 0x4056a207, 0x4d7a, 0x4cd5, 0xa4, 0x19, 0x2e, 0x46, 0x90, 0xdc, 0x70, 0x5e);

typedef struct _MFT_REGISTER_TYPE_INFO { GUID guidMajorType; GUID guidSubtype; } MFT_REGISTER_TYPE_INFO;
typedef struct _PropVariant {
    uint16_t vt; uint16_t wReserved1, wReserved2, wReserved3;
    union { int32_t l; uint32_t ul; int64_t hVal; uint64_t uhVal; LPVOID p; int boolVal; } u;
} PROPVARIANT;
#define VT_UI4 3
#define VT_BOOL 11

typedef struct IMFAttributes IMFAttributes;
typedef IMFAttributes IMFMediaType;
typedef struct IMFSample IMFSample;
typedef struct IMFMediaBuffer IMFMediaBuffer;
typedef struct IMFTransform IMFTransform;
typedef struct ICodecAPI ICodecAPI;
typedef struct IMFActivate IMFActivate;

struct IMFAttributesVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IMFAttributes *, const IID *, void **);
    uint32_t (STDMETHODCALLTYPE *AddRef)(IMFAttributes *);
    uint32_t (STDMETHODCALLTYPE *Release)(IMFAttributes *);
    HRESULT (STDMETHODCALLTYPE *GetItem)(IMFAttributes *, const GUID *, PROPVARIANT *);
    HRESULT (STDMETHODCALLTYPE *GetItemType)(IMFAttributes *, const GUID *, int32_t *);
    HRESULT (STDMETHODCALLTYPE *CompareItem)(IMFAttributes *, const GUID *, const PROPVARIANT *, BOOL *);
    HRESULT (STDMETHODCALLTYPE *Compare)(IMFAttributes *, IMFAttributes *, int32_t, BOOL *);
    HRESULT (STDMETHODCALLTYPE *GetUINT32)(IMFAttributes *, const GUID *, UINT32 *);
    HRESULT (STDMETHODCALLTYPE *GetUINT64)(IMFAttributes *, const GUID *, UINT64 *);
    HRESULT (STDMETHODCALLTYPE *GetDouble)(IMFAttributes *, const GUID *, double *);
    HRESULT (STDMETHODCALLTYPE *GetGUID)(IMFAttributes *, const GUID *, GUID *);
    HRESULT (STDMETHODCALLTYPE *GetStringLength)(IMFAttributes *, const GUID *, UINT32 *);
    HRESULT (STDMETHODCALLTYPE *GetString)(IMFAttributes *, const GUID *, WCHAR *, UINT32, UINT32 *);
    HRESULT (STDMETHODCALLTYPE *GetBlobSize)(IMFAttributes *, const GUID *, UINT32 *);
    HRESULT (STDMETHODCALLTYPE *GetBlob)(IMFAttributes *, const GUID *, BYTE *, UINT32, UINT32 *);
    HRESULT (STDMETHODCALLTYPE *GetUnknown)(IMFAttributes *, const GUID *, const IID *, void **);
    HRESULT (STDMETHODCALLTYPE *SetItem)(IMFAttributes *, const GUID *, const PROPVARIANT *);
    HRESULT (STDMETHODCALLTYPE *DeleteItem)(IMFAttributes *, const GUID *);
    HRESULT (STDMETHODCALLTYPE *DeleteAllItems)(IMFAttributes *);
    HRESULT (STDMETHODCALLTYPE *SetUINT32)(IMFAttributes *, const GUID *, UINT32);
    HRESULT (STDMETHODCALLTYPE *SetUINT64)(IMFAttributes *, const GUID *, UINT64);
    HRESULT (STDMETHODCALLTYPE *SetDouble)(IMFAttributes *, const GUID *, double);
    HRESULT (STDMETHODCALLTYPE *SetGUID)(IMFAttributes *, const GUID *, const GUID *);
    HRESULT (STDMETHODCALLTYPE *SetStringLength)(IMFAttributes *, const GUID *, UINT32);
    HRESULT (STDMETHODCALLTYPE *SetString)(IMFAttributes *, const GUID *, LPCWSTR);
    HRESULT (STDMETHODCALLTYPE *SetBlob)(IMFAttributes *, const GUID *, const BYTE *, UINT32);
    HRESULT (STDMETHODCALLTYPE *SetUnknown)(IMFAttributes *, const GUID *, void *);
    HRESULT (STDMETHODCALLTYPE *LockStore)(IMFAttributes *);
    HRESULT (STDMETHODCALLTYPE *UnlockStore)(IMFAttributes *);
    HRESULT (STDMETHODCALLTYPE *GetCount)(IMFAttributes *, UINT32 *);
    HRESULT (STDMETHODCALLTYPE *GetItemByIndex)(IMFAttributes *, UINT32, GUID *, PROPVARIANT *);
    HRESULT (STDMETHODCALLTYPE *Clear)(IMFAttributes *);
    HRESULT (STDMETHODCALLTYPE *ChangeType)(IMFAttributes *, const GUID *, int32_t);
    HRESULT (STDMETHODCALLTYPE *CopyAllItems)(IMFAttributes *, IMFAttributes *);
};
struct IMFAttributes { struct IMFAttributesVtbl *lpVtbl; };
/* IMFMediaType 在真实 SDK 中继承 IMFAttributes 且无自有方法；stub 用 typedef 保证
   IMFMediaType* → IMFAttributes* 隐式兼容（与 SDK 语义一致） */
typedef struct IMFAttributes IMFMediaType;

struct IMFMediaBufferVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IMFMediaBuffer *, const IID *, void **);
    uint32_t (STDMETHODCALLTYPE *AddRef)(IMFMediaBuffer *);
    uint32_t (STDMETHODCALLTYPE *Release)(IMFMediaBuffer *);
    HRESULT (STDMETHODCALLTYPE *Lock)(IMFMediaBuffer *, BYTE **, UINT32 *, UINT32 *);
    HRESULT (STDMETHODCALLTYPE *Unlock)(IMFMediaBuffer *);
    HRESULT (STDMETHODCALLTYPE *GetLength)(IMFMediaBuffer *, DWORD *);
    HRESULT (STDMETHODCALLTYPE *GetCurrentLength)(IMFMediaBuffer *, DWORD *);
    HRESULT (STDMETHODCALLTYPE *SetCurrentLength)(IMFMediaBuffer *, DWORD);
    HRESULT (STDMETHODCALLTYPE *GetMaxLength)(IMFMediaBuffer *, DWORD *);
};
struct IMFMediaBuffer { struct IMFMediaBufferVtbl *lpVtbl; };

struct IMFSampleVtbl {
    /* IUnknown + IMFAttributes（顺序继承） */
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IMFSample *, const IID *, void **);
    uint32_t (STDMETHODCALLTYPE *AddRef)(IMFSample *);
    uint32_t (STDMETHODCALLTYPE *Release)(IMFSample *);
    HRESULT (STDMETHODCALLTYPE *GetItem)(IMFSample *, const GUID *, PROPVARIANT *);
    HRESULT (STDMETHODCALLTYPE *GetItemType)(IMFSample *, const GUID *, int32_t *);
    HRESULT (STDMETHODCALLTYPE *CompareItem)(IMFSample *, const GUID *, const PROPVARIANT *, BOOL *);
    HRESULT (STDMETHODCALLTYPE *Compare)(IMFSample *, IMFAttributes *, int32_t, BOOL *);
    HRESULT (STDMETHODCALLTYPE *GetUINT32)(IMFSample *, const GUID *, UINT32 *);
    HRESULT (STDMETHODCALLTYPE *GetUINT64)(IMFSample *, const GUID *, UINT64 *);
    HRESULT (STDMETHODCALLTYPE *GetDouble)(IMFSample *, const GUID *, double *);
    HRESULT (STDMETHODCALLTYPE *GetGUID)(IMFSample *, const GUID *, GUID *);
    HRESULT (STDMETHODCALLTYPE *GetStringLength)(IMFSample *, const GUID *, UINT32 *);
    HRESULT (STDMETHODCALLTYPE *GetString)(IMFSample *, const GUID *, WCHAR *, UINT32, UINT32 *);
    HRESULT (STDMETHODCALLTYPE *GetBlobSize)(IMFSample *, const GUID *, UINT32 *);
    HRESULT (STDMETHODCALLTYPE *GetBlob)(IMFSample *, const GUID *, BYTE *, UINT32, UINT32 *);
    HRESULT (STDMETHODCALLTYPE *GetUnknown)(IMFSample *, const GUID *, const IID *, void **);
    HRESULT (STDMETHODCALLTYPE *SetItem)(IMFSample *, const GUID *, const PROPVARIANT *);
    HRESULT (STDMETHODCALLTYPE *DeleteItem)(IMFSample *, const GUID *);
    HRESULT (STDMETHODCALLTYPE *DeleteAllItems)(IMFSample *);
    HRESULT (STDMETHODCALLTYPE *SetUINT32)(IMFSample *, const GUID *, UINT32);
    HRESULT (STDMETHODCALLTYPE *SetUINT64)(IMFSample *, const GUID *, UINT64);
    HRESULT (STDMETHODCALLTYPE *SetDouble)(IMFSample *, const GUID *, double);
    HRESULT (STDMETHODCALLTYPE *SetGUID)(IMFSample *, const GUID *, const GUID *);
    HRESULT (STDMETHODCALLTYPE *SetStringLength)(IMFSample *, const GUID *, UINT32);
    HRESULT (STDMETHODCALLTYPE *SetString)(IMFSample *, const GUID *, LPCWSTR);
    HRESULT (STDMETHODCALLTYPE *SetBlob)(IMFSample *, const GUID *, const BYTE *, UINT32);
    HRESULT (STDMETHODCALLTYPE *SetUnknown)(IMFSample *, const GUID *, void *);
    HRESULT (STDMETHODCALLTYPE *LockStore)(IMFSample *);
    HRESULT (STDMETHODCALLTYPE *UnlockStore)(IMFSample *);
    HRESULT (STDMETHODCALLTYPE *GetCount)(IMFSample *, UINT32 *);
    HRESULT (STDMETHODCALLTYPE *GetItemByIndex)(IMFSample *, UINT32, GUID *, PROPVARIANT *);
    HRESULT (STDMETHODCALLTYPE *Clear)(IMFSample *);
    HRESULT (STDMETHODCALLTYPE *ChangeType)(IMFSample *, const GUID *, int32_t);
    HRESULT (STDMETHODCALLTYPE *CopyAllItems)(IMFSample *, IMFAttributes *);
    /* IMFSample 自有方法 */
    HRESULT (STDMETHODCALLTYPE *GetSampleFlags)(IMFSample *, UINT32 *);
    HRESULT (STDMETHODCALLTYPE *SetSampleFlags)(IMFSample *, UINT32);
    HRESULT (STDMETHODCALLTYPE *GetSampleTime)(IMFSample *, int64_t *);
    HRESULT (STDMETHODCALLTYPE *SetSampleTime)(IMFSample *, int64_t);
    HRESULT (STDMETHODCALLTYPE *GetSampleDuration)(IMFSample *, int64_t *);
    HRESULT (STDMETHODCALLTYPE *SetSampleDuration)(IMFSample *, int64_t);
    HRESULT (STDMETHODCALLTYPE *GetBufferCount)(IMFSample *, uint32_t *);
    HRESULT (STDMETHODCALLTYPE *GetBufferByIndex)(IMFSample *, uint32_t, IMFMediaBuffer **);
    HRESULT (STDMETHODCALLTYPE *ConvertToContiguousBuffer)(IMFSample *, IMFMediaBuffer **);
    HRESULT (STDMETHODCALLTYPE *AddBuffer)(IMFSample *, IMFMediaBuffer *);
    HRESULT (STDMETHODCALLTYPE *RemoveBufferByIndex)(IMFSample *, uint32_t);
    HRESULT (STDMETHODCALLTYPE *RemoveAllBuffers)(IMFSample *);
    HRESULT (STDMETHODCALLTYPE *GetTotalLength)(IMFSample *, uint32_t *);
    HRESULT (STDMETHODCALLTYPE *CopyToBuffer)(IMFSample *, IMFMediaBuffer *);
};
struct IMFSample { struct IMFSampleVtbl *lpVtbl; };

typedef struct _MFT_OUTPUT_DATA_BUFFER {
    DWORD dwStreamID;
    IMFSample *pSample;
    DWORD dwStatus;
    void *pEvents;
} MFT_OUTPUT_DATA_BUFFER;
#define MFT_OUTPUT_DATA_BUFFER_FORMAT_CHANGE 0x00000100u
#define MFT_OUTPUT_DATA_BUFFER_INCOMPLETE 0x01000000u

typedef struct _MFT_OUTPUT_STREAM_INFO {
    DWORD dwFlags;
    DWORD cbSize;
    DWORD cbAlignment;
} MFT_OUTPUT_STREAM_INFO;

struct IMFTransformVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(IMFTransform *, const IID *, void **);
    uint32_t (STDMETHODCALLTYPE *AddRef)(IMFTransform *);
    uint32_t (STDMETHODCALLTYPE *Release)(IMFTransform *);
    HRESULT (STDMETHODCALLTYPE *GetAttributes)(IMFTransform *, IMFAttributes **);
    HRESULT (STDMETHODCALLTYPE *SetInputType)(IMFTransform *, DWORD, IMFMediaType *, UINT32);
    HRESULT (STDMETHODCALLTYPE *GetInputAvailableType)(IMFTransform *, DWORD, DWORD, IMFMediaType **);
    HRESULT (STDMETHODCALLTYPE *SetOutputType)(IMFTransform *, DWORD, IMFMediaType *, UINT32);
    HRESULT (STDMETHODCALLTYPE *GetOutputAvailableType)(IMFTransform *, DWORD, DWORD, IMFMediaType **);
    HRESULT (STDMETHODCALLTYPE *GetInputCurrentType)(IMFTransform *, DWORD, IMFMediaType **);
    HRESULT (STDMETHODCALLTYPE *GetOutputCurrentType)(IMFTransform *, DWORD, IMFMediaType **);
    HRESULT (STDMETHODCALLTYPE *GetInputStatus)(IMFTransform *, DWORD, DWORD *);
    HRESULT (STDMETHODCALLTYPE *GetOutputStatus)(IMFTransform *, DWORD *);
    HRESULT (STDMETHODCALLTYPE *SetInputBounds)(IMFTransform *, int64_t, int64_t);
    HRESULT (STDMETHODCALLTYPE *GetInputBounds)(IMFTransform *, int64_t *, int64_t *);
    HRESULT (STDMETHODCALLTYPE *ProcessEvent)(IMFTransform *, DWORD, void *);
    HRESULT (STDMETHODCALLTYPE *ProcessMessage)(IMFTransform *, int32_t, uintptr_t);
    HRESULT (STDMETHODCALLTYPE *ProcessInput)(IMFTransform *, DWORD, IMFSample *, UINT32);
    HRESULT (STDMETHODCALLTYPE *ProcessOutput)(IMFTransform *, UINT32, uint32_t,
                                               MFT_OUTPUT_DATA_BUFFER *, UINT32 *);
};
struct IMFTransform { struct IMFTransformVtbl *lpVtbl; };

/* MFT_MESSAGE_*（Msg 值，MSDN） */
#define MFT_MESSAGE_NOTIFY_BEGIN_STREAMING 0x0000000A
#define MFT_MESSAGE_NOTIFY_START_OF_STREAM 0x0000000C
#define MFT_MESSAGE_NOTIFY_END_OF_STREAM   0x0000000D
#define MFT_MESSAGE_NOTIFY_END_STREAMING   0x0000000F
#define MFT_MESSAGE_COMMAND_FLUSH          0x00000001
#define MFT_MESSAGE_COMMAND_DRAIN          0x00000003

struct ICodecAPIVtbl {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(ICodecAPI *, const IID *, void **);
    uint32_t (STDMETHODCALLTYPE *AddRef)(ICodecAPI *);
    uint32_t (STDMETHODCALLTYPE *Release)(ICodecAPI *);
    HRESULT (STDMETHODCALLTYPE *IsSupported)(ICodecAPI *, const GUID *);
    HRESULT (STDMETHODCALLTYPE *IsModifiable)(ICodecAPI *, const GUID *);
    HRESULT (STDMETHODCALLTYPE *GetParameterRange)(ICodecAPI *, const GUID *, void *, void *, void *);
    HRESULT (STDMETHODCALLTYPE *GetParameterValues)(ICodecAPI *, const GUID *, void **, uint32_t *);
    HRESULT (STDMETHODCALLTYPE *GetDefaultValue)(ICodecAPI *, const GUID *, void *);
    HRESULT (STDMETHODCALLTYPE *GetValue)(ICodecAPI *, const GUID *, void *);
    HRESULT (STDMETHODCALLTYPE *SetValue)(ICodecAPI *, const GUID *, void *);
    HRESULT (STDMETHODCALLTYPE *SetValueWithNotify)(ICodecAPI *, const GUID *, void *, GUID **, uint32_t *);
    HRESULT (STDMETHODCALLTYPE *RegisterForEvent)(ICodecAPI *, const GUID *, uintptr_t);
    HRESULT (STDMETHODCALLTYPE *UnregisterForEvent)(ICodecAPI *, const GUID *);
    HRESULT (STDMETHODCALLTYPE *SetAllDefaults)(ICodecAPI *);
    HRESULT (STDMETHODCALLTYPE *SetValueWithNotify2)(ICodecAPI *);
    HRESULT (STDMETHODCALLTYPE *GetAllSettings)(ICodecAPI *, void *);
    HRESULT (STDMETHODCALLTYPE *SetAllSettings)(ICodecAPI *, void *);
    HRESULT (STDMETHODCALLTYPE *GetAllSettingsWithNotify)(ICodecAPI *, void *, GUID **, uint32_t *);
    HRESULT (STDMETHODCALLTYPE *SetAllSettingsWithNotify)(ICodecAPI *, void *, GUID **, uint32_t *);
};
struct ICodecAPI { struct ICodecAPIVtbl *lpVtbl; };

/* MF API（导出自 mfplat.dll） */
#define MF_SDK_VERSION 0x0002
#define MF_VERSION_MAJOR 2
#define MF_API_VERSION 0x0070
#define MF_VERSION ((MF_SDK_VERSION << 16) | MF_API_VERSION)
#define MFSTARTUP_LITE 0x1
#define COINIT_MULTITHREADED 0x0
#define MFT_ENUM_FLAG_SYNCMFT 0x00000001
#define MF_MT_FIXED_SIZE_SAMPLES_ATTR 0
#define MFGetAttributeUINT32(a, g, d) (d)

HRESULT MFStartup(uint32_t version, uint32_t flags);
HRESULT MFShutdown(void);
HRESULT MFCreateMediaType(IMFMediaType **);
HRESULT MFTEnumEx(const GUID, uint32_t, const MFT_REGISTER_TYPE_INFO *,
                  const MFT_REGISTER_TYPE_INFO *, void ***, uint32_t *);
HRESULT MFCreateSample(IMFSample **);
HRESULT MFCreateMemoryBuffer(uint32_t, IMFMediaBuffer **);
#define MFSetAttributeSize(t, g, w, h) (t)->lpVtbl->SetUINT64((IMFAttributes *)(t), g, ((UINT64)(w) << 32) | (UINT64)(h))
#define MFSetAttributeRatio(t, g, n, d) (t)->lpVtbl->SetUINT64((IMFAttributes *)(t), g, ((UINT64)(n) << 32) | (UINT64)(d))
/* eAVEncH264VProfile_Base */
#define eAVEncH264VProfile_Base 66
/* Interlace 模式：2 = 渐进 */
#define MFVideoInterlace_Progressive 2
HRESULT CoInitializeEx(LPVOID, uint32_t);
void CoUninitialize(void);

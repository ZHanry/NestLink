// Kernel-handle cleanup only; no COM/D3D object is moved off its original worker.
// Never remotely close an announced numeric handle: it may have been reused.
#pragma once
#include <mutex>
class SharedRingRetirementLedger {
    using Compare=BOOL(WINAPI*)(HANDLE,HANDLE);
    struct Record {
        HANDLE peer=nullptr;
        std::array<HANDLE,3> sources{};
        std::array<uint64_t,3> remote{};
        bool retired=false;
        void reset() {for(auto& source:sources)if(source){CloseHandle(source);source=nullptr;}if(peer){CloseHandle(peer);peer=nullptr;}remote={};retired=false;}
        ~Record(){reset();}
    };
    std::mutex gate;
    std::array<Record,8> records;
    Compare compare=reinterpret_cast<Compare>(GetProcAddress(GetModuleHandleW(L"kernelbase.dll"),"CompareObjectHandles"));
    void sweep() {
        for(auto& record:records) {
            if(!record.peer || !record.retired)continue;
            if(WaitForSingleObject(record.peer,0)==WAIT_OBJECT_0){record.reset();continue;}
            bool outstanding=false;
            for(size_t index=0;index<record.remote.size();++index) {
                if(!record.remote[index])continue;
                HANDLE observed=nullptr;
                // This duplicates only for inspection. It never closes or
                // mutates a handle in the destination, even after pipe EOF.
                if(DuplicateHandle(record.peer,reinterpret_cast<HANDLE>(static_cast<uintptr_t>(record.remote[index])),
                    GetCurrentProcess(),&observed,0,FALSE,DUPLICATE_SAME_ACCESS)) {
                    const bool original=compare && compare(observed,record.sources[index]);
                    CloseHandle(observed);
                    if(original || !compare)outstanding=true;else record.remote[index]=0;
                } else if(GetLastError()==ERROR_INVALID_HANDLE)record.remote[index]=0;
                else outstanding=true;
            }
            if(!outstanding)record.reset();
        }
    }
public:
    static SharedRingRetirementLedger& instance(){static SharedRingRetirementLedger value;return value;}
    HRESULT reserve(HANDLE peer,size_t* result) {
        std::lock_guard<std::mutex> lock(gate);
        if(!peer || !result || !compare)return E_NOTIMPL;
        sweep();size_t same=0,free=records.size();
        for(size_t index=0;index<records.size();++index) {
            const auto& record=records[index];
            if(!record.peer){if(free==records.size())free=index;continue;}
            if(compare(peer,record.peer))++same;
        }
        // Includes current and uncertain retired exports. A silent/abandoned
        // destination cannot accumulate an unbounded set of shared textures.
        if(same>=3 || free==records.size())return HRESULT_FROM_WIN32(ERROR_NOT_ENOUGH_QUOTA);
        auto& record=records[free];
        if(!DuplicateHandle(GetCurrentProcess(),peer,GetCurrentProcess(),&record.peer,0,FALSE,DUPLICATE_SAME_ACCESS))return HRESULT_FROM_WIN32(GetLastError());
        *result=free;return S_OK;
    }
    void abandon(size_t index) {
        std::lock_guard<std::mutex> lock(gate);
        if(index<records.size())records[index].reset();
    }
    void retire(size_t index,std::array<HANDLE,3> sources,const std::array<uint64_t,3>& remote) {
        std::lock_guard<std::mutex> lock(gate);
        if(index>=records.size())return;
        auto& record=records[index];record.sources=sources;record.remote=remote;record.retired=true;
        sweep();
    }
};

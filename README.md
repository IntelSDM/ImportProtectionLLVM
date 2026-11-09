# Import Protection For LLVM
Built for LLVM 19.1 - Windows x64 <br> <br>

Most Obfuscators use lazy importing to protect their obfuscation, That is a pretty poor technique that has always failed to automated analysis as you know the hashing algo, you know the output, you know it will be in the EAT walk, so you simply had to automate those components <br>
Import Protection on the other hand removes the EAT walk entirely, directly doing moduleaddress + RVA, then decrypts utilizing a blake3 integrity check of the imported function. This means we skip EAT and IAT hooks and fail the call and crash downstream if an inline hook is present. <br>
The downside is... You NEED a build server to do this, you can't do this in a single bin, you need to be running a DRM that can collect a build server. <br>
The upsides (despite the intended anti hooking and analysis benefits), is AI MCPs don't have the imports on their disks, they need to flood their context with over 20mb of system32 files to analyse the binary. Sure optimisations can trim it, but the more damage you can do to the context, the worse the output, higher hallucination chances. <br>
It is advised to do this early into the pipeline too so your MBA, CFF, and integrity checks go over top to help hide the RVA and the intentions. <br>
<br>
Import Protection does support delayed imports. 


<img width="880" height="549" alt="image" src="https://github.com/user-attachments/assets/0378e0db-6631-4b2b-b9bc-19d1d0c2aebf" /> <br>
sub_140001000 is the blake 3 checksum(funcstart,size), it decrypts using the checksum so if the import is tampered, it silently fails. <br>

## How to use
* First of all you need a build server that already grabs the users dll info. DLLGrabberUtility.h Is how you grab the info from the user, Call GrabIdentity on their end. 
* Then once we have the TimeDateStamp SizeOfImage DllName from the user, we can query the DLLs directly from Microsoft's download server; as seen in OfficialDLLDownloader.h.
* So you now have the dlls from your user from Microsoft's server, they are on disk, you then use the DLLExportGrabber.h on them, use them in the pass. 
* Each Windows build has a unique build. 
* Then cache the output, if the user has a repeat build with the same DLLs, you then give them the existing output, otherwise you build them a new one for their windows build

## Annotations
```c
__attribute__((annotate("importprot")))
``` 
* Activates Import Protection On Function

## How To Build
* Download [LLVM 19.1](https://github.com/llvm/llvm-project/releases/tag/llvmorg-19.1.0)
* Download [VCPKG](https://github.com/microsoft/vcpkg)
* VCPKG install asmjit
* Open build.bat in a text editor.
* Find the LLVM 19.1 references in the command line, Change them to your file path.
* Find the VCPKG references in the command line, Change them to your file path.
* Run the build script
* Build your application with the ``` -load-pass-plugin ``` Param to the FunctionPass.dll

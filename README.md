PoSH-Sodium
===========

PoSH-Sodium is a powershell module that uses the [libsodium-net](https://github.com/adamcaudill/libsodium-net) library.

Why
===

Scripts deserve encryption too.

Status
======

libsodium-net is experimental, therefore so is PoSH-Sodium.  Not all methods have been implemented.

Installation
============

PoSH-Sodium is a powershell module, so to install you'll need to run import-module on PoSH-Sodium.dll.  There are currently no release builds for PoSH-Sodium so to start, clone the source and build.  The source comes with a submodule Pester for powershell testing.  To clone the project with the submodule, perform the following:

    git clone https://github.com/jamessantiago/PoSH-Sodium.git PoSH-Sodium
    cd PoSH-Sodium
    git submodules init
    git submodule update

Testing
=======

[Latest Test Results](http://htmlpreview.github.io/?https://github.com/jamessantiago/PoSH-Sodium/blob/master/PesterTesting/LastTestResults.html)

After you build the code you can execute powershell tests by updating and running the Pester.ps1 script or navigating to the PesterTesting directory and running the pester.bat script located in Pester\bin.

Available Cmdlets
=================

So far these are available:

    Convert-PrivateKey [-PrivateKey] <byte[]> [<CommonParameters>]
    Convert-PublicKey [-PublicKey] <byte[]> [<CommonParameters>]
    Decrypt-Message [-Message] <string> [-Nonce] <byte[]> [-PublicKey] <byte[]> [-PrivateKey] <byte[]> [-Raw] [[-Encoding] <string>] [<CommonParameters>]
    Decrypt-RawMessage [-Message] <byte[]> [-Nonce] <byte[]> [-PublicKey] <byte[]> [-PrivateKey] <byte[]> [-Raw] [[-Encoding] <string>] [<CommonParameters>]
    Decrypt-RawSymmetricMessage [-Message] <byte[]> [-Nonce] <byte[]> [-Key] <byte[]> [-Raw] [[-Encoding] <string>] [<CommonParameters>]
    Decrypt-SymmetricMessage [-Message] <string> [-Nonce] <byte[]> [-Key] <byte[]> [-Raw] [[-Encoding] <string>] [<CommonParameters>]
    Encrypt-Message [-Message] <string> [-PrivateKey] <byte[]> [-PublicKey] <byte[]> [-Raw] [[-Encoding] <string>] [<CommonParameters>]
    Encrypt-SymmetricMessage [-Message] <string> [-Key] <byte[]> [-Raw] [[-Encoding] <string>] [<CommonParameters>]
    New-CurveKeyPair [[-PrivateKey] <byte[]>] [<CommonParameters>]
    New-Key [<CommonParameters>]
    New-KeyPair [[-Seed] <byte[]>] [<CommonParameters>]
    New-OneTimeKey [<CommonParameters>]
    Sign-Message [-Message] <string> [-Key] <byte[]> [-Raw] [[-Encoding] <string>] [<CommonParameters>]
    Sign-OneTime [-Message] <string> [-Key] <byte[]> [-Raw] [[-Encoding] <string>] [<CommonParameters>]
    Sign-SymmetricMessage [-Message] <string> [-Key] <byte[]> [-Raw] [[-Encoding] <string>] [[-HashType] <string>] [<CommonParameters>]
    Verify-Message [-Message] <string> [-Key] <byte[]> [-SignatureOnly] [-Raw] [[-Encoding] <string>] [<CommonParameters>]
    Verify-OneTime [-Message] <string> [-Key] <byte[]> [-Signature] <string> [[-Encoding] <string>] [<CommonParameters>]
    Verify-RawMessage [-Message] <byte[]> [-Key] <byte[]> [-SignatureOnly] [-Raw] [[-Encoding] <string>] [<CommonParameters>]
    Verify-RawOneTime [-Message] <string> [-Key] <byte[]> [-Signature] <byte[]> [[-Encoding] <string>] [<CommonParameters>]
    Verify-RawSymmetricMessage [-Message] <string> [-Key] <byte[]> [-Signature] <byte[]> [[-Encoding] <string>] [[-HashType] <string>] [<CommonParameters>]
    Verify-SymmetricMessage [-Message] <string> [-Key] <byte[]> [-Signature] <string> [[-Encoding] <string>] [[-HashType] <string>] [<CommonParameters>]

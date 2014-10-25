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

PoSH-Sodium is a powershell module, so to install you'll need to run import-module on PoSH-Sodium.dll.  There are currently no release builds for PoSH-Sodium so to start, clone the source and build.  The source comes with the submodule Pester for powershell testing and Nunit-HTML-Report-Generator for generating the HTML test report.  To clone the project with the submodules, perform the following:

    git clone --recursive https://github.com/jamessantiago/PoSH-Sodium.git PoSH-Sodium

If you are using an earlier version of git than version 1.6.5, run these commands:

    git clone https://github.com/jamessantiago/PoSH-Sodium.git PoSH-Sodium
    cd PoSH-Sodium
    git submodules init
    git submodule update

Testing
=======

[Latest Test Results](http://htmlpreview.github.io/?https://github.com/jamessantiago/PoSH-Sodium/blob/master/PesterTesting/LastTestResults.html)

The testing goal for PoSH-Sodium is 100% test coverage.  You can run the tests by running the RunTests.bat file under the PesterTesting directory.

Usage
=====

PoSH-Sodium commands can be used after building the source and importing PoSH-Sodium.dll.

Available Cmdlets
=================

So far these are available:

    ConvertFrom-JsonKey [-Key] <string> [<CommonParameters>]
    ConvertFrom-Key [-Key] <byte[]> [[-KeyName] <string>] [<CommonParameters>]
    ConvertFrom-Key [-KeyPair] <KeyPair> [[-KeyName] <string>] [<CommonParameters>]
    Convert-PrivateKey [-PrivateKey] <byte[]> [<CommonParameters>]
    Convert-PublicKey [-PublicKey] <byte[]> [<CommonParameters>]
    Decrypt-ChaChaMessage [-Message] <string> [-Nonce] <byte[]> [-Key] <byte[]> [-Raw] [[-Encoding] <string>] [<CommonParameters>]
    Decrypt-Message [-Message] <string> [-PrivateKey] <byte[]> [-PublicKey] <byte[]> [-Raw] [[-Encoding] <string>] [<CommonParameters>]
    Decrypt-Message [-RawMessage] <byte[]> [-PrivateKey] <byte[]> [-PublicKey] <byte[]> [-Raw] [<CommonParameters>]
    Decrypt-Message [-File] <string> [-PrivateKey] <byte[]> [-PublicKey] <byte[]> [[-OutFile] <string>] [-ReplaceFile] [<CommonParameters>]
    Decrypt-RawChaChaMessage [-Message] <byte[]> [-Nonce] <byte[]> [-Key] <byte[]> [-Raw] [[-Encoding] <string>] [<CommonParameters>]
    Decrypt-RawXSalsaMessage [-Message] <byte[]> [-Nonce] <byte[]> [-Key] <byte[]> [-Raw] [[-Encoding] <string>] [<CommonParameters>]
    Decrypt-SymmetricMessage [-Message] <string> [-Nonce] <byte[]> [-Key] <byte[]> [-Raw] [[-Encoding] <string>] [<CommonParameters>]
    Decrypt-SymmetricMessage [-RawMessage] <byte[]> [-Nonce] <byte[]> [-Key] <byte[]> [-Raw] [<CommonParameters>]
    Decrypt-SymmetricMessage [-File] <string> [-Key] <byte[]> [[-OutFile] <string>] [-ReplaceFile] [<CommonParameters>]
    Decrypt-XSalsaMessage [-Message] <string> [-Nonce] <byte[]> [-Key] <byte[]> [-Raw] [[-Encoding] <string>] [<CommonParameters>]
    Encrypt-ChaChaMessage [-Message] <string> [-Key] <byte[]> [-Raw] [[-Encoding] <string>] [<CommonParameters>]
    Encrypt-Message [-Message] <string> [-PrivateKey] <byte[]> [-PublicKey] <byte[]> [-Raw] [[-Encoding] <string>] [<CommonParameters>]
    Encrypt-Message [-RawMessage] <byte[]> [-PrivateKey] <byte[]> [-PublicKey] <byte[]> [-Raw] [<CommonParameters>]
    Encrypt-Message [-File] <string> [-PrivateKey] <byte[]> [-PublicKey] <byte[]> [[-OutFile] <string>] [-ReplaceFile] [<CommonParameters>]
    Encrypt-SymmetricMessage [-Message] <string> [-Key] <byte[]> [-Raw] [[-Encoding] <string>] [<CommonParameters>]
    Encrypt-SymmetricMessage [-RawMessage] <byte[]> [-Key] <byte[]> [-Raw] [<CommonParameters>]
    Encrypt-SymmetricMessage [-File] <string> [-Key] <byte[]> [[-OutFile] <string>] [-ReplaceFile] [<CommonParameters>]
    Encrypt-XSalsaMessage [-Message] <string> [-Key] <byte[]> [-Raw] [[-Encoding] <string>] [<CommonParameters>]
    New-CurveKeyPair [[-PrivateKey] <byte[]>] [<CommonParameters>]
    New-GenericHash [-Message] <string> [[-HashLength] <int>] [[-Key] <byte[]>] [-Raw] [[-Encoding] <string>] [<CommonParameters>]
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

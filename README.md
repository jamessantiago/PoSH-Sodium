PoSH-Sodium
===========

PoSH-Sodium is a powershell module that uses the [libsodium-net](https://github.com/adamcaudill/libsodium-net) library.

Demo
====

![image](https://raw.githubusercontent.com/jamessantiago/PoSH-Sodium/master/Demo.gif)

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

Right now there are no releases.  PoSH-Sodium is still in early development.  If you would like to test, the following method will get you started:

 - Clone the repository
 - Build the source
 - Use the DeployModule.ps1 script in the PesterTesting project or use the import-module command on the PoSH-Sodium.dll file

 You'll need the powershell tools for Visual Studio 2013 to fully access the PesterTesting project.

Available Cmdlets
=================

So far these are available:
    
    ConvertTo-CurveKey
    Decrypt-Message
    Decrypt-SymmetricMessage
    Encrypt-Message
    Encrypt-SymmetricMessage
    New-CurveKeyPair
    New-GenericHash
    New-Key
    New-KeyPair
    New-OneTimeKey
    Sign-Message
    Sign-OneTime
    Sign-SymmetricMessage
    Verify-Message
    Verify-OneTime
    Verify-RawMessage
    Verify-RawOneTime
    Verify-RawSymmetricMessage
    Verify-SymmetricMessage
    

echo "Setting up environment"
set sodiumBuild=Debug
call "%VS120COMNTOOLS%\..\..\VC\vcvarsall.bat" x86_amd64

echo "Building PoSH-Sodium"
MSBuild ..\PoSH-Sodium.sln /p:Configuration=Debug /p:Platform="Any CPU"

echo "Running tests"
cmd /c ..\PesterFork\bin\pester.bat

echo "Generating report"
IF NOT EXIST "..\Nunit-HTML-Report-Generator\NUnit HTML Report Generator\bin\Debug\NUnitHTMLReportGenerator.exe" MSBuild "..\Nunit-HTML-Report-Generator\NUnit HTML Report Generator.sln" /p:Configuration=Debug /p:Platform="Any CPU"
del LastTestResults.html
call "..\Nunit-HTML-Report-Generator\NUnit HTML Report Generator\bin\Debug\NUnitHTMLReportGenerator.exe" Test.xml LastTestResults.html
pause
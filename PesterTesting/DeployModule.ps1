$debug = New-Object System.Management.Automation.Host.ChoiceDescription "&Debug", "Debug"
$release = New-Object System.Management.Automation.Host.ChoiceDescription "&Release", "Release"
$options = [System.Management.Automation.Host.ChoiceDescription[]]($debug, $release)
$selectBuild = $host.ui.PromptForChoice("Build Selection", "Select the build type you would like to use", $options, 0) 

$count = 0
$paths = $env:PSModulePath.Split(';')
write-Host "Checking if already deployed"
 $paths |% {
	$count++
	$opt = new-Object System.Management.Automation.Host.ChoiceDescription "&$count $_", $_
	$opts += [System.Management.Automation.Host.ChoiceDescription[]]($opt)
	if (test-Path "$_\PoSH-Sodium")
	{
		rm "$_\PoSH-Sodium" -Recurse -Force
		write-Host "Removed PoSH-Sodium from $_" -ForegroundColor yellow
	}
	
}

$selectPath = $host.ui.PromptForChoice("Path Selection", "Select the module path you would like to use", $opts, 0)

if (!(test-Path "$($paths[$selectPath])\PoSH-Sodium"))
{
	mkdir "$($paths[$selectPath])\PoSH-Sodium" | out-Null
}

if ($selectBuild -eq 0)
{
	cp D:\Code\PoSH-Sodium\PoSH-Sodium\bin\Debug\* "$($paths[$selectPath])\PoSH-Sodium"
}
else
{
	cp D:\Code\PoSH-Sodium\PoSH-Sodium\bin\Release\* "$($paths[$selectPath])\PoSH-Sodium"
}

write-Host "PoSH-Sodium deployed to $($paths[$selectPath])\PoSH-Sodium"
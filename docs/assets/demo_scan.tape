# Assay demo: scan a project for uninstrumented LLM calls

Output docs/assets/demo_scan.gif

Set Shell "zsh"
Set FontSize 15
Set Width 880
Set Height 480
Set Padding 16
Set Theme "Catppuccin Mocha"
Set TypingSpeed 50ms

# Hidden setup: PATH and cd to demo project
Hide
Type "export PATH=/Users/timmymacbookpro/Library/Python/3.9/bin:$PATH"
Enter
Sleep 0.5s
Type "cd /tmp/demo_project"
Enter
Sleep 0.5s
Type "clear"
Enter
Sleep 0.5s
Show

Type "assay scan ."
Enter
Sleep 3s

# Let the viewer read the results
Sleep 5s

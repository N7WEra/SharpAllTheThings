
## Pull All Repos down via Unix or WSL (Scripts written by [ZephrFish](https://twitter.com/ZephrFish))
```
./SharpBuilderAll.sh
```
The script will make the following directories and pull a copy of each project down to the respective folder:
```
Execution
Persistence
PrivEsc
DefenseEvasion
CredAccess
Discovery
LateralMovement
Exfil
```

Once all the repos are pulled down time to build them all, note: this assumes devbuild.exe is in the following path `C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\devenv.exe`.

Thanks to https://twitter.com/BufferOfStyx for help on the bash trickery to get the paths all looking good, if you're interested `for i in $(find . -name 2>/dev/null *.sln | sed 's/\//\\/g'); do echo "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\IDE\devenv.exe" $i /Build "Release|x64"; done`, this can be altered for your path to devenv.exe.

The builder script will take the bat file as an input and assumes it is in the same directory(BuildAllTheThings.bat)

```
BuildAllTheThings.bat
```

NOTE: this will error for some solutions and still a work in progress! 

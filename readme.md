= StellarStellaris =

Patching Stellaris in memory to enhance performance, especially late game.

== WARNING WARNING WARNING ==

This is pre-Beta software, use at your own risk. It only attaches in memory, so ultimately if it breaks something you can just restart the game, but it could corrupt a save or cause crashes. If it does, please let me know by opening a github issue.

Currently there are no binaries provided and you'll need to compile it yourself if you'd like to use it.


== What it does ==
This app currently applies patches to a running instance of (linux) Stellaris to improve performance and fix bugs. In the future it may add modding functionality.

== How it does it? ==
It uses pre-defined memory addresses and the ptrace API to patch in new code or assembly of a running process in memory. All the patched issues are found by hand by me with a dissassembler and debugger. This is fairly painstaking and slow as there is no source code, only assembly machine code.

== Background / Why does it exist ==
I am a high level systems engineer that usually does work for large corporations on large, distributed, applications. In my past experience one of my primary specialties has been finding performance issues and bugs/design flaws in unknown codebases. Because of some of the jobs I've had, I've worked in a multitude of programming and scripting languages (C, C++, C#, Java, Visual Basic, Python, PHP, JavaScript, Assembly, Lua, perl, SAS, R, VHDL, COBOL, etc). That said, I'm not really a software developer. Most of my job experience has been in finding and fixing problems in complex systems (hundreds or thousands of servers running dozens of applications) in a high pressure environment with extremely tight timelines (IE: hours).

I also have about 2000 hours in Stellaris. I've almost always been dissapointed with late game performance, so I finally decided to apply my skillset to the game, and reached out to some of the Paradox team on LinkedIn and offered to provide my services to find and fix problems, for free, and I even said I was willing to sign a non disclosure agreement and intellectual property rights assignments for any work I did (basically, make sure their bases are covered legally). Unfortunately I got no response, so I decided to start looking into it "the hard way" by doing it without any code, via a disassembler and debugger.

This code is the result of my work, which I hope to expand in the future. I'd really like to improve the moddability of the game, ideally by adding a embedded lua interpreter with access to more of the internals of the game, but that may be a bit too lofty of a goal without access to the code. At the least I'd like to expand GUI modability, as I'd really like a megastructure GUI and more sidebar buttons for mods.

If you'd like to support my work so I can spend more time on it you can contribute to my Patreon at <link>


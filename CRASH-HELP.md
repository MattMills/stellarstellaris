Troubleshooting Stellaris Crashes:

Generally, the error logs are NOT useful for diagnosing crashes, but it doesn't hurt to look at, if something is consistently happening in the log directly before you crash (for example, a mod added event is throwing errors), that may help explain it. Also, it may just make more sense to start a new game if you're running into a lot of crashiness, but if you'd like to try to figure it out:


OS | Crash Dir 
------------- | -------------
Windows | %userprofile%\Documents\Paradox Interactive\Stellaris\crashes\
Linux | ~/.local/share/Paradox Interactive/Stellaris/crashes/
Mac | no clue


1. What OS?
    1. If you are using Mac or Linux, your crash exception log (exception.txt in crash dir) may have more detail than on Windows.
	  2. If you are using Windows, what renderer are you using? You may want to try the different options as some renderers can crash on certain gfx related file issues.
2. What Version of Stellaris?
3. Vanilla or Modded?
    1. If you have a reproducible vanilla crash, you should report it to Paradox as they will investigate and try to fix it, also if you have a modded crash you can diagnose and reproduce in vanilla you can report that too.
4. Is your crash date consistent?
    1. If yes, you can check your save file for timed events on that date and remove them.
    2. If yes, is the crash date a monthly or yearly tick (IE, year.01.01 or year.month.01)?
        1. If you are clicking the screen or doing anything during monthly or yearly ticks that can cause crashes, don't.
	      2. Try deleting as many armies as you can, assault then buildings or edicts that create defense armies.
	  3. If yes, you can try reloading your save and deleting / disbanding things. (Make sure you KEEP your save if you use autosaves). If you disband a group and it stops crashing, you can check those things 1 by 1 until you find the specific thing that is causing your crash, reload your save, disband that one thing, and you should be good to go.
		    1. Armies
		    2. Fleets
		    3. Starbases
		    4. Shipyards
		    5. Civilian ships (I haven't seen any crashes here personally).
5. If you've gotten this far down and still don't have an answer:
    1. Check system event logs for obvious hardware issues
    2. Memtest doesn't hurt
    3. You can open the minidump.dmp in WinDBG or Visual studio, but even if you know what you're doing it can be hard to diagnose as Stellaris doesn't provide debug symbols.
    4. If you can provide a crash reproducing save and an export of all mods from irony mod manager (export ... -> export whole collection should produce a zip file containing all mods), I MIGHT be willing to diagnose it for you if you message me on the Stellaris modding den discord (@matt_mills), but I reserve the right to ignore you.

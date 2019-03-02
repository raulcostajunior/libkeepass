The *kpass* Console Application
===================================

I. Command line syntax
----------------------
<pre>
    <b>kpass</b> [-c] <i>file_path</i>
</pre>

Where ``-c ``, *create command*, is an optional parameter that tells *kpass* to create a new KeePass file.  ``file_path`` is the path of the KeePass file to be created. If ``-c`` is not in the command line, ``file_path`` is interpreted as the path of an existing KeePass file to be opened.

If a command line with an invalid syntax is provided, a helping message describing the expected syntax is displayed and *kpass* exits. If *kpass* is invoked in create mode with the path of an already existing file, an error message is displayed and *kpass* exits. If *kpass* is invoked in open file mode (command line with no *create command*), *kpass* checks if ``file_path`` corresponds to a valid KeePass file. If that is not the case, an error message is displayed and *kpass* exits.

When invoked in create mode, *kpass* prompts for the password for the new KeePass file and for its confirmation. After a valid password is provided (minimum 6 characters) and confirmed, *kpass* launches its "shell".

When invoked in open mode, *kpass* prompts for the KeePass file password. If the right password is provided, *kpass* launches its "shell". 

II. Commands Supported by the *kpass "Shell"*
---------------------------------------------

III. Settings Supported by *kpass*
----------------------------------

IV. Password Record Templates
-----------------------------

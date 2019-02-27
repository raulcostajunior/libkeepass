The **`kpass`** Console Application
===================================

I. Command line syntax
----------------------

    kpass [file_path]

Where `file_path` is an optional argument and is the name of the keepass cyphered file to be opened. If an existing file path is provided, `kpass` will prompt the user for a master password to open the file - support for key files will not be implemented yet.

If a valid command line is used to launch `kpass`, the kpass "shell" will be started. A command line is considered valid if it conforms to the expected syntax and if it provides a path to an existing file (whenever the `file_path` argument is used). If a command line with an invalid syntax is provided, a helping message describing the expected syntax is shown to the user and `kpass` exits. If a syntatically valid command line is provided, but with an inexisting `file_path`, an error is displayed to the user and `kpass` exits.

II. Commands Supported by the `kpass` "Shell"
---------------------------------------------

III. Settings Supported by `kpass`
----------------------------------

IV. Password Record Templates
-----------------------------

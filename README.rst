=======
 ``encrypthis``
=======

What?
----
A CLI to encrypt / decrypt files and directories (including images and non-text), with some path filtering options, inspired by fd_.

Install
----

    pip install encrypthis


Examples
----

**encrypt**::

    encrypt password.txt -o encrypted-password.txt
    encrypt image.png file.py -o encrypted/
    encrypt /my/dir/ -o /my/encrypted-dir/ --file-filter png py


**decrypt**::

    decrypt encrypted-password.txt -o password.txt
    decrypt /my/encrypted-dir/ -o /my/dir/

-----------------------------------------------------------------------

``encrypthis`` is careful to not overwrite files, and is generous with confirmation prompts before making any changes.

.. [#fd] https://github.com/sharkdp/fd
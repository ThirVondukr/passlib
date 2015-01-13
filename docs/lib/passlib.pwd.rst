.. module:: passlib.pwd
	:synopsis: password generation helpers

=================================================
:mod:`passlib.pwd` -- password generation helpers
=================================================

.. versionadded:: 1.7

.. todo::
    This module is still a work in progress, it's API may change
    before release. See module source for detailed todo list.

Generation
==========
.. warning::

    Before using these routines, be sure your system's RNG state is safe,
    and that you use a sufficiently high ``entropy`` value for
    the intended purpose.

.. autofunction:: generate(size=None, entropy=None, count=None, preset=None, charset=None, wordset=None, spaces=True)

.. rst-class:: html-toggle

Generator Backends
------------------
The following classes are used by the :func:`generate` function behind the scenes,
to perform word- and phrase- generation. They are useful for folks who want
a little more information about the password generation process, and/or
want to use a preconfigured generator.

.. autoclass:: SecretGenerator
.. autoclass:: WordGenerator
.. autoclass:: PhraseGenerator

Analysis
========
.. warning::

    *Disclaimer:*
    There can be no accurate estimate of the quality of a password,
    because it depends on too many conditions that are unknowable from just
    looking at the password. This code attempts to rule out the worst passwords,
    and identify potentially-weak passwords, but should be used only as a guide.

.. autofunction:: strength
.. autofunction:: classify

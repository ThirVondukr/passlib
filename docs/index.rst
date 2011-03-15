==========================================
PassLib |release| documentation
==========================================

Introduction
============
PassLib is a library for managing password hashes,
with support for over 18 current and historical :doc:`password hash schemes <lib/passlib.hash>`.
It can be used for a variety of purposes:

    * cross-platform replacement for stdlib's ``crypt()``.
    * encrypting & verifying most known hash formats used by:
        - Linux & BSD shadow files
        - Apache htpasswd files
        - MySQL & PostgreSQL user account tables
    * drop-in password hashing for new python applications.
    * building a configurable hashing policy
      for python applications to migrate existing hashing schemes.

See the :doc:`Library Overview <overview>` for more details.

Quick Links
===========

.. raw:: html

  <table class="contentstable" align="center">
  <tr>
    <td width="50%" valign="top">
      <p class="biglink"><a class="biglink" href="contents.html">Table of Contents</a><br>
         <span class="linkdescr">lists all sections and subsections</span></p>

          <p class="biglink"><a class="biglink" href="overview.html">Library Overview</a><br>
         <span class="linkdescr">describes how PassLib is laid out</span></p>

    </td><td width="50%">

      <p class="biglink"><a class="biglink" href="genindex.html">General Index</a><br>
         <span class="linkdescr">all functions, classes, terms</span></p>

      <p class="biglink"><a class="biglink" href="py-modindex.html">Module List</a><br>
         <span class="linkdescr">quick access to all modules</span></p>

      <p class="biglink"><a class="biglink" href="search.html">Search Page</a><br>
         <span class="linkdescr">search this documentation</span></p>

    </td></tr>
  </table>

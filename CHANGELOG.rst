.. _changelog:

<!-- version list -->

.. _changelog-v5.0.0:

v5.0.0 (2025-05-09)
===================

✨ Features
-----------

* Adding some helper functions (`0c18d8f`_)

* Follow up on the new campus network Portal authentication encryption (`405cd6d`_)

* Refactor log management (`760b10d`_)

* Remove get_default_interface() because the value it obtained was not accurate. (`11b91b7`_)

* Switched from psutil to lighter-weight ifaddr. (`3215dc5`_)

🪲 Bug Fixes
------------

* A field error (`f2195b5`_)

* Correct local address assignment logic (`34ee351`_)

* Encrypt password using the correct encryption (`5c5b15d`_)

♻️ Refactoring
---------------

* Reorder imports across modules for consistency (`f9fb0a5`_)

🤖 Continuous Integration
-------------------------

* Update the release workflow to use workflow_dispatch trigger (`27b702b`_)

🧹 Chores
---------

* Add release note template (`8148935`_)

* **deps**: Update astral-sh/setup-uv action to v6 (`PR#10`_, `88716b1`_)

* **deps**: Update python-semantic-release/publish-action action to v9.21.1 (`PR#11`_, `d56d36a`_)

* **deps**: Update python-semantic-release/python-semantic-release action to v9.21.1 (`PR#12`_,
  `0fe7403`_)

.. _0c18d8f: https://github.com/Illustar0/ZZU.Py/commit/0c18d8f0a49d2d4f288668bf1e0560ba02271d84
.. _0fe7403: https://github.com/Illustar0/ZZU.Py/commit/0fe74031b85b33d0980de0218a7a19110fcaa8e2
.. _11b91b7: https://github.com/Illustar0/ZZU.Py/commit/11b91b706ac705ac83ce6d1c1c1358bb8927b672
.. _27b702b: https://github.com/Illustar0/ZZU.Py/commit/27b702b42ab8dd2081a6e909285f17953ea5a613
.. _3215dc5: https://github.com/Illustar0/ZZU.Py/commit/3215dc54ba8bc4c80af1407161b34eb98ddcff0c
.. _34ee351: https://github.com/Illustar0/ZZU.Py/commit/34ee3518267cc4acb1e09c01c7be8a0d630891ab
.. _405cd6d: https://github.com/Illustar0/ZZU.Py/commit/405cd6d099b5c843e389e300eb58a2d215186809
.. _5c5b15d: https://github.com/Illustar0/ZZU.Py/commit/5c5b15dcf45cae94fb7515911ec06341e5fa5ab3
.. _760b10d: https://github.com/Illustar0/ZZU.Py/commit/760b10d76f4485093d70d738302d52627bc09db5
.. _8148935: https://github.com/Illustar0/ZZU.Py/commit/8148935f117464f11edbf899f98fc1f4e5dba4fb
.. _88716b1: https://github.com/Illustar0/ZZU.Py/commit/88716b13ff0862eb728e9978b055546e26fe3627
.. _d56d36a: https://github.com/Illustar0/ZZU.Py/commit/d56d36adf2e91c2d423f743b4ee56413dfd01ea3
.. _f2195b5: https://github.com/Illustar0/ZZU.Py/commit/f2195b5164f5fa1bbf2a77b2fe85b722ab92463b
.. _f9fb0a5: https://github.com/Illustar0/ZZU.Py/commit/f9fb0a5a2e0e68d9d8d1e00a40cec8b113a27284
.. _PR#10: https://github.com/Illustar0/ZZU.Py/pull/10
.. _PR#11: https://github.com/Illustar0/ZZU.Py/pull/11
.. _PR#12: https://github.com/Illustar0/ZZU.Py/pull/12


.. _changelog-v4.1.0:

v4.1.0 (2025-03-18)
===================

✨ Features
-----------

* Automatically obtain cur_semester_id and biz_type_id and use them as default values (`5b7c6e3`_)

* Support obtain semester data (`1c1e223`_)

* Support query of empty classrooms (`f05ef9b`_)

🪲 Bug Fixes
------------

* Corrected some error request bodies (`e003214`_)

📖 Documentation
----------------

* Add credits (`440f50c`_)

* Add models.rst (`9658a97`_)

* Enable sphinx to parse pydantic models (`b79e726`_)

* Update features (`2a28eba`_)

♻️ Refactoring
---------------

* Format code (`daffc76`_)

.. _1c1e223: https://github.com/Illustar0/ZZU.Py/commit/1c1e223ca1a71ea2c5cd24d39cb369579d6c2241
.. _2a28eba: https://github.com/Illustar0/ZZU.Py/commit/2a28eba2a94957dd7556b37c5c82eeb35e1c22d1
.. _440f50c: https://github.com/Illustar0/ZZU.Py/commit/440f50c2a1b8762e90e604f4af63eee93ba6dedf
.. _5b7c6e3: https://github.com/Illustar0/ZZU.Py/commit/5b7c6e3bfffa0f98fcdbd5e3ed0774151ccd860e
.. _9658a97: https://github.com/Illustar0/ZZU.Py/commit/9658a97153ab8bec101288b3f28020162481d782
.. _b79e726: https://github.com/Illustar0/ZZU.Py/commit/b79e72685b7ac08a4d68c1b59b5793b981c77b53
.. _daffc76: https://github.com/Illustar0/ZZU.Py/commit/daffc764da425dbbf0ba4530b3b3266de173c44e
.. _e003214: https://github.com/Illustar0/ZZU.Py/commit/e003214b7109db987d018b9e18c13ca3cb8d5408
.. _f05ef9b: https://github.com/Illustar0/ZZU.Py/commit/f05ef9b1c7e331e336f2eac4864a6cd40028d30d


.. _changelog-v4.0.0:

v4.0.0 (2025-03-08)
===================

✨ Features
-----------

* Allows obtaining userToken via public API (`aff8a3c`_)

* Make login() return a dictionary (`5c6963c`_)

* Use pydantic to provide type annotations (`e02d25c`_)

🪲 Bug Fixes
------------

* Allow specifying semester_id for get_courses() (`faa0388`_)

* Remove useless imports (`d0fa47a`_)

📖 Documentation
----------------

* Modify the comment format (`0509e3f`_)

* Update README.md (`71ced68`_)

💥 Breaking Changes
-------------------

* Get_courses() required parameters changed

* Login() return value changed

.. _0509e3f: https://github.com/Illustar0/ZZU.Py/commit/0509e3f18722e2908fef11e9b3eea71a6761b7fe
.. _5c6963c: https://github.com/Illustar0/ZZU.Py/commit/5c6963ca2c4334effe9be513961b5cd0fbb29de9
.. _71ced68: https://github.com/Illustar0/ZZU.Py/commit/71ced688c89293c96e6ca1aaebcd50de4eb773ec
.. _aff8a3c: https://github.com/Illustar0/ZZU.Py/commit/aff8a3c93f2e4d4e7bd55c7c019b5c44a7f07b44
.. _d0fa47a: https://github.com/Illustar0/ZZU.Py/commit/d0fa47a0874e00b4849328c844cc7d071e623337
.. _e02d25c: https://github.com/Illustar0/ZZU.Py/commit/e02d25c6f90e820e51a6be6cf746f84a69bfcf5f
.. _faa0388: https://github.com/Illustar0/ZZU.Py/commit/faa0388a663a676fa985b65c50e11d5418ff626d


.. _changelog-v3.0.0:

v3.0.0 (2025-03-05)
===================

✨ Features
-----------

* Introducing support for async io (`87fb608`_)

* Use SimpleCookie as the incoming type (`286be07`_)

🪲 Bug Fixes
------------

* Type hint error (`86f2e23`_)

📖 Documentation
----------------

* Complete documentation for some internal functions (`6552735`_)

* Correct and complete some documents (`220f1da`_)

💥 Breaking Changes
-------------------

* No longer accepting dict type cookies

.. _220f1da: https://github.com/Illustar0/ZZU.Py/commit/220f1daacb9d4c3c559c3cc612fefa238428cd23
.. _286be07: https://github.com/Illustar0/ZZU.Py/commit/286be07343b08b671797bd3c9397616ad49b850f
.. _6552735: https://github.com/Illustar0/ZZU.Py/commit/655273564b03b9d0bc8b3b89372d74b9f210fcdf
.. _86f2e23: https://github.com/Illustar0/ZZU.Py/commit/86f2e2336ab45c41d78b6061753c05c06cb32829
.. _87fb608: https://github.com/Illustar0/ZZU.Py/commit/87fb6080df89bcef60eb2b66a274fcc868cd9f81


.. _changelog-v2.1.0:

v2.1.0 (2025-03-03)
===================

✨ Features
-----------

* Automatically refresh ecard_access_token (`d7770d9`_)

* More detailed exceptions (`da19688`_)

* Perform permission check before operation (`6378e4a`_)

🪲 Bug Fixes
------------

* Forgot to delete the httpx top-level API (`4a94ff5`_)

* Prevent program exit from being blocked (`cdebda4`_)

* Wrong location_type in headers (`30017fa`_)

⚡ Performance Improvements
---------------------------

* Reduce duplication of code (`53b6844`_)

* Remove unused functions (`b07c0af`_)

♻️ Refactoring
---------------

* Format code (`d70974f`_)

.. _30017fa: https://github.com/Illustar0/ZZU.Py/commit/30017fa4e0a76f60dfbe0630dd7aa1a8b8507f55
.. _4a94ff5: https://github.com/Illustar0/ZZU.Py/commit/4a94ff56b672b33eee2af6d651fe4a40e744afa7
.. _53b6844: https://github.com/Illustar0/ZZU.Py/commit/53b68444fe8cc559d35c0dc2bae88fce6104a30e
.. _6378e4a: https://github.com/Illustar0/ZZU.Py/commit/6378e4a2d9b9733b9b81e59715e6a66003f65031
.. _b07c0af: https://github.com/Illustar0/ZZU.Py/commit/b07c0af4365e3754c547b73598c14e874bd4d92a
.. _cdebda4: https://github.com/Illustar0/ZZU.Py/commit/cdebda4d37d408e0fef808d8cd4b5dc31426b5b3
.. _d70974f: https://github.com/Illustar0/ZZU.Py/commit/d70974f223c736cfe9ef7360573428e974241062
.. _d7770d9: https://github.com/Illustar0/ZZU.Py/commit/d7770d9715a3344e67193ba1396ebe608f4939c7
.. _da19688: https://github.com/Illustar0/ZZU.Py/commit/da19688c8c4dec44aa10b4b22eebf4de9ae570ab


.. _changelog-v2.0.1:

v2.0.1 (2025-03-02)
===================

🪲 Bug Fixes
------------

* Unable to generate document (`b29393a`_)

.. _b29393a: https://github.com/Illustar0/ZZU.Py/commit/b29393ae56679d5975349e2da2b77a043c5b0805


.. _changelog-v2.0.0:

v2.0.0 (2025-03-02)
===================

✨ Features
-----------

* Allow cookie login (`ebb159e`_)

* Bump app version (`16e9544`_)

* Initial exception handling (`94faba3`_)

* Support for getting the default room (`d0d7437`_)

♻️ Refactoring
---------------

* Format code (`b3c81ad`_)

* Optimize imports (`caceaa9`_)

🤖 Continuous Integration
-------------------------

* Fix the wrong command (`25e764f`_)

* Modify commit message (`0c49df9`_)

🧹 Chores
---------

* Replace poetry with uv (`e9da782`_)

* Update build command (`85ee7fc`_)

* Update renovate config (`ec18baf`_)

* Update version_toml (`96c3a3f`_)

* **deps**: Update python-semantic-release/publish-action action to v9.19.1 (`PR#2`_, `6b98903`_)

* **deps**: Update python-semantic-release/publish-action action to v9.20.0 (`PR#5`_, `ed0a9f3`_)

* **deps**: Update python-semantic-release/publish-action action to v9.21.0 (`PR#7`_, `1364b87`_)

* **deps**: Update python-semantic-release/python-semantic-release action to v9.19.1 (`PR#3`_,
  `3dd61a9`_)

* **deps**: Update python-semantic-release/python-semantic-release action to v9.20.0 (`PR#6`_,
  `b8db4f7`_)

* **deps**: Update python-semantic-release/python-semantic-release action to v9.21.0 (`PR#8`_,
  `6d8550a`_)

💥 Breaking Changes
-------------------

* Room parameter position adjustment

.. _0c49df9: https://github.com/Illustar0/ZZU.Py/commit/0c49df983a0fb3eae037009ac8b6fdab74cfbff7
.. _1364b87: https://github.com/Illustar0/ZZU.Py/commit/1364b87966a21d49b650240e0a7156903061e91d
.. _16e9544: https://github.com/Illustar0/ZZU.Py/commit/16e9544a3a4332b59480c4211a110ffdc64dafa0
.. _25e764f: https://github.com/Illustar0/ZZU.Py/commit/25e764f9aa89472789dfee124a210eb423cf7c7c
.. _3dd61a9: https://github.com/Illustar0/ZZU.Py/commit/3dd61a94b56a5ace9ad73c7491bd8fb13e6eb424
.. _6b98903: https://github.com/Illustar0/ZZU.Py/commit/6b989035ae02b4385344c828ab071880a84ff66a
.. _6d8550a: https://github.com/Illustar0/ZZU.Py/commit/6d8550ab665a43d2560f7e4b522bb547c9a8f560
.. _85ee7fc: https://github.com/Illustar0/ZZU.Py/commit/85ee7fc67e670b894620a41eb65dfe3d93792712
.. _94faba3: https://github.com/Illustar0/ZZU.Py/commit/94faba31954e8a1fc27429c46efc06f8850f1748
.. _96c3a3f: https://github.com/Illustar0/ZZU.Py/commit/96c3a3f8ac686c5817f0cd424c6363411b70098a
.. _b3c81ad: https://github.com/Illustar0/ZZU.Py/commit/b3c81ada9437e0d7e54fa8746019b5e579ff4fd5
.. _b8db4f7: https://github.com/Illustar0/ZZU.Py/commit/b8db4f7096277f2c953428696c7dd39d839ccf09
.. _caceaa9: https://github.com/Illustar0/ZZU.Py/commit/caceaa9172856143d3b865388a5c675298ff81e0
.. _d0d7437: https://github.com/Illustar0/ZZU.Py/commit/d0d74372b06cfaa5a2a5fe195853e4e8faf8d05c
.. _e9da782: https://github.com/Illustar0/ZZU.Py/commit/e9da782c4d57d4f7b02d5181f75ae2f49d996899
.. _ebb159e: https://github.com/Illustar0/ZZU.Py/commit/ebb159e7a193c9a8c64f1450024ef7750d38f36e
.. _ec18baf: https://github.com/Illustar0/ZZU.Py/commit/ec18baff35af8d44d05d7f7bee0a6720e2395642
.. _ed0a9f3: https://github.com/Illustar0/ZZU.Py/commit/ed0a9f36edf0402bd0f234ef8010bec3ced41b8c
.. _PR#2: https://github.com/Illustar0/ZZU.Py/pull/2
.. _PR#3: https://github.com/Illustar0/ZZU.Py/pull/3
.. _PR#5: https://github.com/Illustar0/ZZU.Py/pull/5
.. _PR#6: https://github.com/Illustar0/ZZU.Py/pull/6
.. _PR#7: https://github.com/Illustar0/ZZU.Py/pull/7
.. _PR#8: https://github.com/Illustar0/ZZU.Py/pull/8


.. _changelog-v1.0.2:

v1.0.2 (2025-02-09)
===================


.. _changelog-v1.0.1:

v1.0.1 (2025-02-09)
===================

🪲 Bug Fixes
------------

* Fix a field error that caused the version to fail to be published (`e7615ca`_)

* License error (`1f85a71`_)

* Type error (`a9c82f1`_)

🧹 Chores
---------

* Change license (`3186cbc`_)

.. _1f85a71: https://github.com/Illustar0/ZZU.Py/commit/1f85a71df95363daa9017e967dc57836fc42a201
.. _3186cbc: https://github.com/Illustar0/ZZU.Py/commit/3186cbceeec150516989cc78874811afda6d6972
.. _a9c82f1: https://github.com/Illustar0/ZZU.Py/commit/a9c82f15919e0249439d15d332b117d2062af0c1
.. _e7615ca: https://github.com/Illustar0/ZZU.Py/commit/e7615caea2fc73b33096147000f250d8f1402be6



.. _changelog-v1.0.0:

v1.0.0 (2015-08-04)
===================

💥 Breaking
-----------

* Restructure helpers into history and pypi (`00f64e6`_)

📖 Documentation
----------------

* Add automatic publishing documentation, resolves `#18`_ (`58076e6`_)

.. _#18: https://github.com/python-semantic-release/python-semantic-release/issues/18
.. _00f64e6: https://github.com/python-semantic-release/python-semantic-release/commit/00f64e623db0e21470d55488c5081e12d6c11fd3
.. _58076e6: https://github.com/python-semantic-release/python-semantic-release/commit/58076e60bf20a5835b112b5e99a86c7425ffe7d9


.. _changelog-v0.9.1:

v0.9.1 (2015-08-04)
===================

🪲 Bug Fixes
------------

* Fix ``get_current_head_hash`` to ensure it only returns the hash (`7c28832`_)

.. _7c28832: https://github.com/python-semantic-release/python-semantic-release/commit/7c2883209e5bf4a568de60dbdbfc3741d34f38b4


.. _changelog-v0.9.0:

v0.9.0 (2015-08-03)
===================

✨ Features
-----------

* Add Python 2.7 support, resolves `#10`_ (`c05e13f`_)

.. _#10: https://github.com/python-semantic-release/python-semantic-release/issues/10
.. _c05e13f: https://github.com/python-semantic-release/python-semantic-release/commit/c05e13f22163237e963c493ffeda7e140f0202c6


.. _changelog-v0.8.0:

v0.8.0 (2015-08-03)
===================

✨ Features
-----------

* Add ``check_build_status`` option, resolves `#5`_ (`310bb93`_)

* Add ``get_current_head_hash`` in git helpers (`d864282`_)

* Add git helper to get owner and name of repo (`f940b43`_)

.. _#5: https://github.com/python-semantic-release/python-semantic-release/issues/5
.. _310bb93: https://github.com/python-semantic-release/python-semantic-release/commit/310bb9371673fcf9b7b7be48422b89ab99753f04
.. _d864282: https://github.com/python-semantic-release/python-semantic-release/commit/d864282c498f0025224407b3eeac69522c2a7ca0
.. _f940b43: https://github.com/python-semantic-release/python-semantic-release/commit/f940b435537a3c93ab06170d4a57287546bd8d3b


.. _changelog-v0.7.0:

v0.7.0 (2015-08-02)
===================

✨ Features
-----------

* Add ``patch_without_tag`` option, resolves `#6`_ (`3734a88`_)

📖 Documentation
----------------

* Set up sphinx based documentation, resolves `#1`_ (`41fba78`_)

.. _#1: https://github.com/python-semantic-release/python-semantic-release/issues/1
.. _#6: https://github.com/python-semantic-release/python-semantic-release/issues/6
.. _3734a88: https://github.com/python-semantic-release/python-semantic-release/commit/3734a889f753f1b9023876e100031be6475a90d1
.. _41fba78: https://github.com/python-semantic-release/python-semantic-release/commit/41fba78a389a8d841316946757a23a7570763c39


.. _changelog-v0.6.0:

v0.6.0 (2015-08-02)
===================

✨ Features
-----------

* Add twine for uploads to pypi, resolves `#13`_ (`eec2561`_)

.. _#13: https://github.com/python-semantic-release/python-semantic-release/issues/13
.. _eec2561: https://github.com/python-semantic-release/python-semantic-release/commit/eec256115b28b0a18136a26d74cfc3232502f1a6


.. _changelog-v0.5.4:

v0.5.4 (2015-07-29)
===================

🪲 Bug Fixes
------------

* Add python2 not supported warning (`e84c4d8`_)

.. _e84c4d8: https://github.com/python-semantic-release/python-semantic-release/commit/e84c4d8b6f212aec174baccd188185627b5039b6


.. _changelog-v0.5.3:

v0.5.3 (2015-07-28)
===================

⚙️ Build System
---------------

* Add ``wheel`` as a dependency (`971e479`_)

.. _971e479: https://github.com/python-semantic-release/python-semantic-release/commit/971e4795a8b8fea371fcc02dc9221f58a0559f32


.. _changelog-v0.5.2:

v0.5.2 (2015-07-28)
===================

🪲 Bug Fixes
------------

* Fix python wheel tag (`f9ac163`_)

.. _f9ac163: https://github.com/python-semantic-release/python-semantic-release/commit/f9ac163491666022c809ad49846f3c61966e10c1


.. _changelog-v0.5.1:

v0.5.1 (2015-07-28)
===================

🪲 Bug Fixes
------------

* Fix push commands (`8374ef6`_)

.. _8374ef6: https://github.com/python-semantic-release/python-semantic-release/commit/8374ef6bd78eb564a6d846b882c99a67e116394e


.. _changelog-v0.5.0:

v0.5.0 (2015-07-28)
===================

✨ Features
-----------

* Add setup.py hook for the cli interface (`c363bc5`_)

.. _c363bc5: https://github.com/python-semantic-release/python-semantic-release/commit/c363bc5d3cb9e9a113de3cd0c49dd54a5ea9cf35


.. _changelog-v0.4.0:

v0.4.0 (2015-07-28)
===================

✨ Features
-----------

* Add publish command (`d8116c9`_)

.. _d8116c9: https://github.com/python-semantic-release/python-semantic-release/commit/d8116c9dec472d0007973939363388d598697784


.. _changelog-v0.3.2:

v0.3.2 (2015-07-28)
===================

* No change


.. _changelog-v0.3.1:

v0.3.1 (2015-07-28)
===================

🪲 Bug Fixes
------------

* Fix wheel settings (`1e860e8`_)

.. _1e860e8: https://github.com/python-semantic-release/python-semantic-release/commit/1e860e8a4d9ec580449a0b87be9660a9482fa2a4


.. _changelog-v0.3.0:

v0.3.0 (2015-07-27)
===================

✨ Features
-----------

* Add support for tagging releases (`5f4736f`_)

🪲 Bug Fixes
------------

* Fix issue when version should not change (`441798a`_)

.. _441798a: https://github.com/python-semantic-release/python-semantic-release/commit/441798a223195138c0d3d2c51fc916137fef9a6c
.. _5f4736f: https://github.com/python-semantic-release/python-semantic-release/commit/5f4736f4e41bc96d36caa76ca58be0e1e7931069


.. _changelog-v0.2.0:

v0.2.0 (2015-07-27)
===================

✨ Features
-----------

* added no-operation (``--noop``) mode (`44c2039`_)

⚙️ Build System
---------------

* Swapped pygit2 with gitpython to avoid libgit2 dependency (`8165a2e`_)

.. _44c2039: https://github.com/python-semantic-release/python-semantic-release/commit/44c203989aabc9366ba42ed2bc40eaccd7ac891c
.. _8165a2e: https://github.com/python-semantic-release/python-semantic-release/commit/8165a2eef2c6eea88bfa52e6db37abc7374cccba


.. _changelog-v0.1.1:

v0.1.1 (2015-07-27)
===================

🪲 Bug Fixes
------------

* Fix entry point (`bd7ce7f`_)

.. _bd7ce7f: https://github.com/python-semantic-release/python-semantic-release/commit/bd7ce7f47c49e2027767fb770024a0d4033299fa


.. _changelog-v0.1.0:

v0.1.0 (2024-10-20)
===================

* Initial Release

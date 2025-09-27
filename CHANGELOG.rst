.. _changelog:

<!-- version list -->

.. _changelog-v6.0.0-rc.7:

v6.0.0-rc.7 (2025-09-27)
========================

✨ Features
-----------

* Add automatic token refresh and forced login support (`a51b609`_)

.. _a51b609: https://github.com/Illustar0/ZZU.Py/commit/a51b6095d71079a6cad5aa9d293ed55ba490416f


.. _changelog-v6.0.0-rc.6:

v6.0.0-rc.6 (2025-09-23)
========================

🪲 Bug Fixes
------------

* Prevent logout calls when not authenticated in close method (`26d7ef0`_)

.. _26d7ef0: https://github.com/Illustar0/ZZU.Py/commit/26d7ef02a8f9af3c5f786b91adcc422a8c75be98


.. _changelog-v6.0.0-rc.5:

v6.0.0-rc.5 (2025-09-22)
========================

🪲 Bug Fixes
------------

* Adjust cryptography dependency to >=45.0.3 (`83055db`_)

.. _83055db: https://github.com/Illustar0/ZZU.Py/commit/83055db4670fe0bb2f4b5e3e9870b63715690847


.. _changelog-v6.0.0-rc.4:

v6.0.0-rc.4 (2025-09-22)
========================

🪲 Bug Fixes
------------

* Adjust pydantic dependency to >=2.11.7 (`dceb164`_)

.. _dceb164: https://github.com/Illustar0/ZZU.Py/commit/dceb164dfac84b09ac4042d67df43fd0a3eff278


.. _changelog-v6.0.0-rc.3:

v6.0.0-rc.3 (2025-09-22)
========================

✨ Features
-----------

* Replace numpy arrays with native lists for schedule matrices (`3027474`_)

.. _3027474: https://github.com/Illustar0/ZZU.Py/commit/30274744285aa2eff3a514863d0cee988e4f7ac5


.. _changelog-v6.0.0-rc.2:

v6.0.0-rc.2 (2025-09-22)
========================

🪲 Bug Fixes
------------

* Lower Python version requirement to >=3.11 (`534d42b`_)

🧹 Chores
---------

* Update issue templates (`e85bc84`_)

🎨 Code Style
-------------

* Format code with ruff (`a50705a`_)

.. _534d42b: https://github.com/Illustar0/ZZU.Py/commit/534d42b53d43a7ae6a1876dc4ae300877c871d88
.. _a50705a: https://github.com/Illustar0/ZZU.Py/commit/a50705acd4b70f819a6d53754b9cbd9aeb020e9f
.. _e85bc84: https://github.com/Illustar0/ZZU.Py/commit/e85bc84087a03caf4cdd7dccd854509311d07245


.. _changelog-v6.0.0-rc.1:

v6.0.0-rc.1 (2025-09-21)
========================

✨ Features
-----------

* Accept account/password in CASClient ctor and centralize token management (`d09f60b`_)

* Add ECardClient for campus ecard services (`48581cc`_)

* Add EPortalClient, SelfServiceSystem and AuthResult model (`96d72c6`_)

* Add ICASClient interface and CASClient CAS authentication client (`fe7c4bb`_)

* Add JsonPParser for parsing JSONP strings (`30f63c5`_)

* Add OperationError to represent operation failures (`3d12153`_)

* Add portal discovery and PortalInfo model (`6f826b7`_)

* Add require_auth decorator for sync and async methods (`6be3774`_)

* Add SupwisdomClient for ZZU Supwisdom teaching system (`f70342e`_)

* Introduce v2 API with complete architecture redesign (`a82f3b5`_)

* Parameterize and harden get_local_ip with safer socket handling (`eb8c77c`_)

* Update LOGIN_URL to CAS token endpoint (`6f33717`_)

* Validate JWTs and cache CAS RSA public key to skip password login (`9bfda28`_)

🪲 Bug Fixes
------------

* Correct decorator order for abstract properties (`31c73a3`_)

* Use correct Transport for EPortalClient when force_bind is False (`6c5aeff`_)

* Use internal _logged_in flag in login-required wrappers (`7ea50f5`_)

📖 Documentation
----------------

* Add "统一认证" section explaining userOnlineDetect and workaround for mobile logout (`2899ac4`_)

* Correct project name from "豫在郑大" to "豫见郑大" (`6a63e2f`_)

* Normalize model annotations (`823bd0f`_)

* Update get_sign implementation details (`8c4b0ef`_)

♻️ Refactoring
---------------

* Add module docstring and import dependencies for decorators and auth (`81ccce5`_)

* Modular redesign with async support and MkDocs migration (`e1e4db2`_)

* Move discover_portal_info from utils to web.network (`a96bb62`_)

* Remove ``_kget`` (`3c40984`_)

* Remove ``sync_wrapper`` (`9a15873`_)

* Remove get_interface_by_ip helper (`eb6d738`_)

* Remove get_ip_by_interface helper (`e0f2897`_)

* Remove OnlineDevices wrapper model (`a72e661`_)

* Remove redundant check_permission helper (`c1e5e2e`_)

* Rename and reorganize exception classes for clarity (`f719c2a`_)

* Replace unnecessary f-strings with plain strings for static endpoints (`397830b`_)

* Replace XOR helper functions with XorCipher class (`f1809b5`_)

* Return List[OnlineDevice] from get_online_devices (`4b5a29d`_)

* Use parse_qs and snake_case param in get_sign (`45439b4`_)

🤖 Continuous Integration
-------------------------

* Add prerelease option to release workflow (`7cfe281`_)

* Switch docs build workflow to MkDocs (`331b0c1`_)

🧹 Chores
---------

* Add numpy and pyjwt to project dependencies (`db2fe1c`_)

* Bump required Python version to ~=3.12 (`a83d86c`_)

* Remove deprecated ``DeviceParams``, ``Courses`` and ``LoginResult`` models (`79c9898`_)

* Remove NOTE.md (`0fcf2c7`_)

* Remove outdated version variable from semantic-release (`cdb168b`_)

* Update project metadata and bump dependencies (`009cc07`_)

🎨 Code Style
-------------

* Format code with ruff (`125e2c9`_)

💥 Breaking Changes
-------------------

* Removes legacy ZZUPy class and Sphinx docs; all APIs now use client-based pattern (e.g.,
  CASClient.login() instead of ZZUPy.login()). Update imports and usage accordingly. Requires Python
  >=3.13 for async features.

* V2 API is not compatible with v1. All method signatures, authentication flow, and data models have
  changed. See MIGRATION.md for v1 to v2 upgrade guide.

.. _009cc07: https://github.com/Illustar0/ZZU.Py/commit/009cc077332ef5c693832d29b913fcef7863401f
.. _0fcf2c7: https://github.com/Illustar0/ZZU.Py/commit/0fcf2c7fdc394719bfc9a36ef6162f4cb0753f17
.. _125e2c9: https://github.com/Illustar0/ZZU.Py/commit/125e2c92ec2962544e700a9285437077602edc7f
.. _2899ac4: https://github.com/Illustar0/ZZU.Py/commit/2899ac4ec60dae8ae0bc8c66939596910958a626
.. _30f63c5: https://github.com/Illustar0/ZZU.Py/commit/30f63c54e43151792182bc545a5a9c3311459797
.. _31c73a3: https://github.com/Illustar0/ZZU.Py/commit/31c73a375a86ea51f7587bd65350c6452c924d62
.. _331b0c1: https://github.com/Illustar0/ZZU.Py/commit/331b0c133281dd23b91408a8df1c1017721ab06e
.. _397830b: https://github.com/Illustar0/ZZU.Py/commit/397830bf07bedf852e080fd733933ae2b9e0e710
.. _3c40984: https://github.com/Illustar0/ZZU.Py/commit/3c40984533f890511c92e7ad867c99011651b6f8
.. _3d12153: https://github.com/Illustar0/ZZU.Py/commit/3d12153b7b425750cf6c5161cab31cbd8e34e53c
.. _45439b4: https://github.com/Illustar0/ZZU.Py/commit/45439b484c61eb99bc7b57921a7673e6e32780b4
.. _48581cc: https://github.com/Illustar0/ZZU.Py/commit/48581cc7603fbba09dfaf3bd123cd98d5e694cc9
.. _4b5a29d: https://github.com/Illustar0/ZZU.Py/commit/4b5a29da184907c15db934e7c73e7895b91ed0fd
.. _6a63e2f: https://github.com/Illustar0/ZZU.Py/commit/6a63e2f06f4d0c574db52c567c5ea42cb7b3392a
.. _6be3774: https://github.com/Illustar0/ZZU.Py/commit/6be37745fd548a08f1719fe161c1e73690d1d4ff
.. _6c5aeff: https://github.com/Illustar0/ZZU.Py/commit/6c5aeff07bad36e85b9799547d5c6ba63346d55e
.. _6f33717: https://github.com/Illustar0/ZZU.Py/commit/6f3371744d84cd993ac378ebf89dbe5335f87fe7
.. _6f826b7: https://github.com/Illustar0/ZZU.Py/commit/6f826b719a8ab8a3511a3784cd973228ccb24c4c
.. _79c9898: https://github.com/Illustar0/ZZU.Py/commit/79c989810c80b691438411ca4d305e32c74a331f
.. _7cfe281: https://github.com/Illustar0/ZZU.Py/commit/7cfe281d34c1c80bebe2ed0535fb581f92f9a011
.. _7ea50f5: https://github.com/Illustar0/ZZU.Py/commit/7ea50f59bdb2ba8899c0579c1a15a60854e5484a
.. _81ccce5: https://github.com/Illustar0/ZZU.Py/commit/81ccce58aa3fb4f9b3b3d573b5d5ef92270136fa
.. _823bd0f: https://github.com/Illustar0/ZZU.Py/commit/823bd0f6d70b2e7c86caee69ae798e12a9208f43
.. _8c4b0ef: https://github.com/Illustar0/ZZU.Py/commit/8c4b0effada40ae69330dc611a2a401a8ef58a0c
.. _96d72c6: https://github.com/Illustar0/ZZU.Py/commit/96d72c6f9d230602776ed58b62225bbee1aa7e19
.. _9a15873: https://github.com/Illustar0/ZZU.Py/commit/9a158739e52b0ec7a42aeb2a868441c96fc0b9ed
.. _9bfda28: https://github.com/Illustar0/ZZU.Py/commit/9bfda2840ff7ebd9318363bd7be0f596357a5bea
.. _a72e661: https://github.com/Illustar0/ZZU.Py/commit/a72e661d556acd1d987e16cc17251991d8fb8d9a
.. _a82f3b5: https://github.com/Illustar0/ZZU.Py/commit/a82f3b50525fb06da296b6ff59714240ed27d315
.. _a83d86c: https://github.com/Illustar0/ZZU.Py/commit/a83d86c438a7b6d6245229ed94a43f192e763e99
.. _a96bb62: https://github.com/Illustar0/ZZU.Py/commit/a96bb629344d337288a285d1c5cee8bcc499734e
.. _c1e5e2e: https://github.com/Illustar0/ZZU.Py/commit/c1e5e2e8c390524352bae8107f22898090c67b4b
.. _cdb168b: https://github.com/Illustar0/ZZU.Py/commit/cdb168b2f9664d04230f4a2fbfef31425ecdb54c
.. _d09f60b: https://github.com/Illustar0/ZZU.Py/commit/d09f60b5d0cca4ec29d7ff0f391e07dcff2d0cd6
.. _db2fe1c: https://github.com/Illustar0/ZZU.Py/commit/db2fe1c9e9cb4a0d24b15e694f8b606dac581672
.. _e0f2897: https://github.com/Illustar0/ZZU.Py/commit/e0f2897f57efd6673d632adcb385b06e247f1126
.. _e1e4db2: https://github.com/Illustar0/ZZU.Py/commit/e1e4db2a7cbccb782eb6e9954cab98016753a85c
.. _eb6d738: https://github.com/Illustar0/ZZU.Py/commit/eb6d7383d4109604fceff4e22b4f20c4fcfc047b
.. _eb8c77c: https://github.com/Illustar0/ZZU.Py/commit/eb8c77cb839792773a0e686740103383965ed809
.. _f1809b5: https://github.com/Illustar0/ZZU.Py/commit/f1809b5fe091d06ce3f2851b159b4659707a63b1
.. _f70342e: https://github.com/Illustar0/ZZU.Py/commit/f70342e27416d5a9cd611718f03f16e245aab79d
.. _f719c2a: https://github.com/Illustar0/ZZU.Py/commit/f719c2aed5e8aad38907b5312642b64a5e65a300
.. _fe7c4bb: https://github.com/Illustar0/ZZU.Py/commit/fe7c4bb1f39579ef14976acc2a8b6e02be918c02


.. _changelog-v5.1.0:

v5.1.0 (2025-05-22)
===================

✨ Features
-----------

* Implement RSA encryption for login credentials (`30d8836`_)

* Update default app version to 1.0.42 (`f18264f`_)

* Update login return type to LoginResult (`8be5926`_)

♻️ Refactoring
---------------

* Add pkcs7_unpad function and integrate into sm4_decrypt_ecb (`a1fbe7b`_)

* Improve imports organization (`5c7a80e`_)

* Remove unnecessary exception handling in network login request (`ecf9dad`_)

* Replace login_sync with login_async in API (`8d46b47`_)

🤖 Continuous Integration
-------------------------

* Rename Continuous Delivery to Release (`74a0753`_)

🧹 Chores
---------

* Correct PyPI URL in release notes template (`ffd6969`_)

* Remove CHANGELOG.md (`f46a875`_)

.. _30d8836: https://github.com/Illustar0/ZZU.Py/commit/30d88364d7cff8ccbbb2ab08474c7f4b57d2e4a9
.. _5c7a80e: https://github.com/Illustar0/ZZU.Py/commit/5c7a80ef58b0b9279a4629967a039cf6998ada8c
.. _74a0753: https://github.com/Illustar0/ZZU.Py/commit/74a075370277c946aba9152fee55a8616f6fafcd
.. _8be5926: https://github.com/Illustar0/ZZU.Py/commit/8be5926df0ce33206e75876b8c9e02a347de8292
.. _8d46b47: https://github.com/Illustar0/ZZU.Py/commit/8d46b47c601c9f153b041bd96fbdff4c77781e26
.. _a1fbe7b: https://github.com/Illustar0/ZZU.Py/commit/a1fbe7bf6056c94d4f375dcc223e1b79c4a28b2d
.. _ecf9dad: https://github.com/Illustar0/ZZU.Py/commit/ecf9dadba910e7cbabe3c11406f8a4cb579966ce
.. _f18264f: https://github.com/Illustar0/ZZU.Py/commit/f18264fd7cf0a294014289d439e561c9067bb903
.. _f46a875: https://github.com/Illustar0/ZZU.Py/commit/f46a87582f070e8d38ce049c0a9b11409018c18a
.. _ffd6969: https://github.com/Illustar0/ZZU.Py/commit/ffd6969e7f48f29e803a9bebfbe9a8f0571993a4


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

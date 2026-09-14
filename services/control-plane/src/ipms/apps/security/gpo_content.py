# File Name: gpo_content.py
# Version: v0.1.0 | Created: 2026-09-14 | Last Modified: 2026-09-14
# Author: Alice Endelgard | Organization: Alvestrasza Corporation
# Description: Generated Microsoft GPO backup trust metadata; no vendor payload bytes.
# Regenerate using scripts/import-security-gpo-packages.py. Do not edit.
import hashlib
import json

CATALOG_SHA256 = 'dafd8ee9ccfff15d077e9e8186680c2dccc834d71c150a98b5d5cb0c0c471c12'
MANIFEST_SCHEMA_VERSION = 1
ARTIFACT_FORMAT = 'IPMSGPO1'
MAX_ARTIFACT_BYTES = 1048576

_CATALOG = json.loads(r'''
{
  "components": [
    {
      "artifact_filename": "f2312f65bfe1f5fc55085c2e42b86d654c7b61d714b175e687bfe88e29c2ee1d.ipmsgpo",
      "artifact_sha256": "f2312f65bfe1f5fc55085c2e42b86d654c7b61d714b175e687bfe88e29c2ee1d",
      "artifact_size": 354302,
      "backup_id": "{202BE0F1-CE9C-4435-BF43-56E18F5BF7D3}",
      "baseline_id": "microsoft-windows-10-22h2",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Applications",
        "DomainSysvol/GPO/Machine/Scripts",
        "DomainSysvol/GPO/Machine/Scripts/Shutdown",
        "DomainSysvol/GPO/Machine/Scripts/Startup",
        "DomainSysvol/GPO/Machine/microsoft",
        "DomainSysvol/GPO/Machine/microsoft/windows nt",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 6149,
          "path": "Backup.xml",
          "sha256": "e51963b47fbe138a71cd4548497f028d7c34493bd5337e9d8b4a88aa4f7a9b52"
        },
        {
          "bytes": 555,
          "path": "DomainSysvol/GPO/Machine/comment.cmtx",
          "sha256": "e6d7b0805b21144958f6b70b5273bd3eab96950b59fbcb1654654f4924cbd35c"
        },
        {
          "bytes": 142,
          "path": "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit/GptTmpl.inf",
          "sha256": "07cba636ed9c1c30c4a4c228e555151f1fc43f7bfc941cbb221ed67297ea3dbc"
        },
        {
          "bytes": 25970,
          "path": "DomainSysvol/GPO/Machine/registry.pol",
          "sha256": "8a5b1628731d7516b4d45144cef6c9aab6e823b62bcd4db226e83c5820e088cc"
        },
        {
          "bytes": 600,
          "path": "bkupInfo.xml",
          "sha256": "3373945e3b2048b3281119ce28f689c1b4f9ae8e818d9557196e5ef357eca078"
        },
        {
          "bytes": 320850,
          "path": "gpreport.xml",
          "sha256": "43cbd90cf259042990682ac8423a84c18e37546437861eb6b0f1a4c9b4c78999"
        }
      ],
      "name": "MSFT Internet Explorer 11 - Computer",
      "purpose": "MSFTInternetExplorer11Computer",
      "scope": "machine",
      "source_backup_path": "Windows-10-v22H2-Security-Baseline/GPOs/{202BE0F1-CE9C-4435-BF43-56E18F5BF7D3}",
      "source_display_name": "MSFT Internet Explorer 11 - Computer",
      "source_gpo_id": "{D5398278-ABE5-4648-921E-D68A15AF59E9}",
      "source_options": 1,
      "source_package_name": "Windows 10 version 22H2 Security Baseline.zip",
      "source_package_sha256": "cbda99d18339ed7445566447323bd1da40b3e31ab7a5fdba1dae024517a52e1a",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2010%20version%2022H2%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "98a30b4a6745ed0d5ad70323ac199689186dd8557046cb913fd2d876fb8961d9.ipmsgpo",
      "artifact_sha256": "98a30b4a6745ed0d5ad70323ac199689186dd8557046cb913fd2d876fb8961d9",
      "artifact_size": 58132,
      "backup_id": "{522ED121-0E11-41F6-A205-CC736B4DEE1E}",
      "baseline_id": "microsoft-windows-10-22h2",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 3615,
          "path": "Backup.xml",
          "sha256": "7871405f64edb585b1c93026a46a42532b565060e912f017409b41a4708af2c3"
        },
        {
          "bytes": 554,
          "path": "DomainSysvol/GPO/Machine/comment.cmtx",
          "sha256": "f4cb5d64e7a8cec20da34b276020efb31262ab81bc325d754578d60f87d5e387"
        },
        {
          "bytes": 5896,
          "path": "DomainSysvol/GPO/Machine/registry.pol",
          "sha256": "6b4a2e6fbff5baab20883d632307673215c0f1136e47baecc8ac9b566bca8658"
        },
        {
          "bytes": 605,
          "path": "bkupInfo.xml",
          "sha256": "3f0e2ea5726c5c3dd835f8b96d49ecb878ea3916312d63e046c0cbc5deddb2ff"
        },
        {
          "bytes": 47430,
          "path": "gpreport.xml",
          "sha256": "ab7591f795c2d3d2205f203160e25be6669b1a57e1028a9bd4e9de86da03d301"
        }
      ],
      "name": "MSFT Windows 10 22H2 - Defender Antivirus",
      "purpose": "MSFTWindows1022H2DefenderAntivirus",
      "scope": "machine",
      "source_backup_path": "Windows-10-v22H2-Security-Baseline/GPOs/{522ED121-0E11-41F6-A205-CC736B4DEE1E}",
      "source_display_name": "MSFT Windows 10 22H2 - Defender Antivirus",
      "source_gpo_id": "{46C96103-F068-4D07-9488-69ED489EFF20}",
      "source_options": 1,
      "source_package_name": "Windows 10 version 22H2 Security Baseline.zip",
      "source_package_sha256": "cbda99d18339ed7445566447323bd1da40b3e31ab7a5fdba1dae024517a52e1a",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2010%20version%2022H2%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "38fb47ac7f65da4bc14732924a4d30344dd39a48c001eca55278fb2a1f3b6c16.ipmsgpo",
      "artifact_sha256": "38fb47ac7f65da4bc14732924a4d30344dd39a48c001eca55278fb2a1f3b6c16",
      "artifact_size": 24275,
      "backup_id": "{816D1B8C-378B-48D9-B2F4-D5E582A57D7C}",
      "baseline_id": "microsoft-windows-10-22h2",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Applications",
        "DomainSysvol/GPO/Machine/Scripts",
        "DomainSysvol/GPO/Machine/Scripts/Shutdown",
        "DomainSysvol/GPO/Machine/Scripts/Startup",
        "DomainSysvol/GPO/Machine/microsoft",
        "DomainSysvol/GPO/Machine/microsoft/windows nt",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 5761,
          "path": "Backup.xml",
          "sha256": "a01a5b6cd9d448b81695f9057408b4e3a4ea2522a3e6952e9d1ea3bfeb1e5b41"
        },
        {
          "bytes": 614,
          "path": "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit/GptTmpl.inf",
          "sha256": "68bff0f76db5c82f3a3db00611190bd792c47d758750b507232bd6d8b17820df"
        },
        {
          "bytes": 602,
          "path": "bkupInfo.xml",
          "sha256": "48e4fdc644e9e30e6aa9a70f63da84485ee5512e8373299bc982d27a292b704d"
        },
        {
          "bytes": 17270,
          "path": "gpreport.xml",
          "sha256": "0a8877870c328fc528ce1065daa4f8745ff5ca75e1e3657e67737273b236fe19"
        }
      ],
      "name": "MSFT Windows 10 22H2 - Domain Security",
      "purpose": "MSFTWindows1022H2DomainSecurity",
      "scope": "domain",
      "source_backup_path": "Windows-10-v22H2-Security-Baseline/GPOs/{816D1B8C-378B-48D9-B2F4-D5E582A57D7C}",
      "source_display_name": "MSFT Windows 10 22H2 - Domain Security",
      "source_gpo_id": "{AA60633F-5B55-4053-B463-A299E1997775}",
      "source_options": 1,
      "source_package_name": "Windows 10 version 22H2 Security Baseline.zip",
      "source_package_sha256": "cbda99d18339ed7445566447323bd1da40b3e31ab7a5fdba1dae024517a52e1a",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2010%20version%2022H2%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "9aaa9f814d88b02ea09f5dbd934a6ad882c2bc22aa1c9c20b74d3fd64e681591.ipmsgpo",
      "artifact_sha256": "9aaa9f814d88b02ea09f5dbd934a6ad882c2bc22aa1c9c20b74d3fd64e681591",
      "artifact_size": 25490,
      "backup_id": "{8C841835-DE87-46E6-98A2-B59B959BFD59}",
      "baseline_id": "microsoft-windows-10-22h2",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Applications",
        "DomainSysvol/GPO/Machine/microsoft",
        "DomainSysvol/GPO/Machine/microsoft/windows nt",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 5069,
          "path": "Backup.xml",
          "sha256": "7ed7aaeb86a374475dd3fa72bf8ddb8801bcb01419fd2550b4189d2ff249c852"
        },
        {
          "bytes": 901,
          "path": "DomainSysvol/GPO/User/comment.cmtx",
          "sha256": "4626e59f12f72f994ce0a1591e5fbcfb1c83cc60462c35d3dff42f745cb0ea30"
        },
        {
          "bytes": 534,
          "path": "DomainSysvol/GPO/User/registry.pol",
          "sha256": "bdc7178487ef6346e2e4796ac6aae54a2076f950cb541bb4bd88c7c4a6874a96"
        },
        {
          "bytes": 596,
          "path": "bkupInfo.xml",
          "sha256": "5170aaebe99cf5e7c6437280a4ddcd32574867454699266ff4d4c1b9d8bbad59"
        },
        {
          "bytes": 18358,
          "path": "gpreport.xml",
          "sha256": "b621b27d74511be9ce05845519021f6a4933c620f6a1a433e6b37bfa850b6f3e"
        }
      ],
      "name": "MSFT Internet Explorer 11 - User",
      "purpose": "MSFTInternetExplorer11User",
      "scope": "user",
      "source_backup_path": "Windows-10-v22H2-Security-Baseline/GPOs/{8C841835-DE87-46E6-98A2-B59B959BFD59}",
      "source_display_name": "MSFT Internet Explorer 11 - User",
      "source_gpo_id": "{582D31BD-8974-43C8-B88B-FC18B4254E87}",
      "source_options": 2,
      "source_package_name": "Windows 10 version 22H2 Security Baseline.zip",
      "source_package_sha256": "cbda99d18339ed7445566447323bd1da40b3e31ab7a5fdba1dae024517a52e1a",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2010%20version%2022H2%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "0db670ec36fceef06679babc1b20376761b77731d9f12afe650e1e218a7558e3.ipmsgpo",
      "artifact_sha256": "0db670ec36fceef06679babc1b20376761b77731d9f12afe650e1e218a7558e3",
      "artifact_size": 300402,
      "backup_id": "{AA94F467-FC14-4789-A1C4-7F74B23184B2}",
      "baseline_id": "microsoft-windows-10-22h2",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Applications",
        "DomainSysvol/GPO/Machine/Scripts",
        "DomainSysvol/GPO/Machine/Scripts/Shutdown",
        "DomainSysvol/GPO/Machine/Scripts/Startup",
        "DomainSysvol/GPO/Machine/microsoft",
        "DomainSysvol/GPO/Machine/microsoft/windows nt",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 8156,
          "path": "Backup.xml",
          "sha256": "d87b8e8983456083da1b6417233cdb293e5c0fe19252f194bb3b2f6c3d60a40e"
        },
        {
          "bytes": 547,
          "path": "DomainSysvol/GPO/Machine/comment.cmtx",
          "sha256": "624d822e257ebc6def32f1efa8d3ac0531b2fd76bbc016190e2f0730d90b405f"
        },
        {
          "bytes": 2208,
          "path": "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit/audit.csv",
          "sha256": "29252c1b507bad5363c730b1a51b4032ec3bde603b3aae8d9425fe3785f44685"
        },
        {
          "bytes": 7346,
          "path": "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit/GptTmpl.inf",
          "sha256": "420fe44948e12f1f0a98d8fc955404a7f2776560cd841b3fae0c10c63315ed6e"
        },
        {
          "bytes": 17754,
          "path": "DomainSysvol/GPO/Machine/registry.pol",
          "sha256": "a423e3d2b84847ff043dc8c1c831fd80c09d04eca08690007490004c748bf79b"
        },
        {
          "bytes": 595,
          "path": "bkupInfo.xml",
          "sha256": "ad37edac4055386db63318cad10abb2ed6cd7cfe664390365f1036bf3787f247"
        },
        {
          "bytes": 263756,
          "path": "gpreport.xml",
          "sha256": "e23f9927adba0be049c0e5206b12dc3c3fc01c25bf3890bba838c568a8f6ffe1"
        }
      ],
      "name": "MSFT Windows 10 22H2 - Computer",
      "purpose": "MSFTWindows1022H2Computer",
      "scope": "machine",
      "source_backup_path": "Windows-10-v22H2-Security-Baseline/GPOs/{AA94F467-FC14-4789-A1C4-7F74B23184B2}",
      "source_display_name": "MSFT Windows 10 22H2 - Computer",
      "source_gpo_id": "{BBFE2BE3-CD4F-43E5-BA96-944725EC478B}",
      "source_options": 1,
      "source_package_name": "Windows 10 version 22H2 Security Baseline.zip",
      "source_package_sha256": "cbda99d18339ed7445566447323bd1da40b3e31ab7a5fdba1dae024517a52e1a",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2010%20version%2022H2%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "3f012ddd9a5e87283bf5f78713cabdac2bc1f389253ae73841ae25cafa0aa317.ipmsgpo",
      "artifact_sha256": "3f012ddd9a5e87283bf5f78713cabdac2bc1f389253ae73841ae25cafa0aa317",
      "artifact_size": 31898,
      "backup_id": "{BA48C326-B51D-47B1-8CED-547FC046DCA7}",
      "baseline_id": "microsoft-windows-10-22h2",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Scripts",
        "DomainSysvol/GPO/Machine/Scripts/Shutdown",
        "DomainSysvol/GPO/Machine/Scripts/Startup",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 4452,
          "path": "Backup.xml",
          "sha256": "143d1919d04bc72c140faa77d5c088e980eaf78915e1dfeee89c05fe7957e67e"
        },
        {
          "bytes": 549,
          "path": "DomainSysvol/GPO/Machine/comment.cmtx",
          "sha256": "94f49ee096c38f34ddf86a3d864661da5a39cca6a641ce5db6c159bf106d8e01"
        },
        {
          "bytes": 1034,
          "path": "DomainSysvol/GPO/Machine/registry.pol",
          "sha256": "1b24281950bda792d454d3887a9ee51d63ee8b6cdf8b883da6695b41d7ab45b2"
        },
        {
          "bytes": 603,
          "path": "bkupInfo.xml",
          "sha256": "1574d694362ca281d346e5559c4b8ab9eac08702ca40f2b0874149b34935f466"
        },
        {
          "bytes": 25228,
          "path": "gpreport.xml",
          "sha256": "2af5f3f31f233dbaf4c151576589c054bc46075cba604ef5a8314657badef9d9"
        }
      ],
      "name": "MSFT Windows 10 22H2 - Credential Guard",
      "purpose": "MSFTWindows1022H2CredentialGuard",
      "scope": "machine",
      "source_backup_path": "Windows-10-v22H2-Security-Baseline/GPOs/{BA48C326-B51D-47B1-8CED-547FC046DCA7}",
      "source_display_name": "MSFT Windows 10 22H2 - Credential Guard",
      "source_gpo_id": "{F38B9CC8-B6F7-4072-B9F3-6989269DF38B}",
      "source_options": 1,
      "source_package_name": "Windows 10 version 22H2 Security Baseline.zip",
      "source_package_sha256": "cbda99d18339ed7445566447323bd1da40b3e31ab7a5fdba1dae024517a52e1a",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2010%20version%2022H2%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "620ac1b4dd755d2d5ec356ab356908a53346e4572252388e662ef885a8e9647b.ipmsgpo",
      "artifact_sha256": "620ac1b4dd755d2d5ec356ab356908a53346e4572252388e662ef885a8e9647b",
      "artifact_size": 24653,
      "backup_id": "{C91CAC2A-3421-404F-A1B6-025301CE3261}",
      "baseline_id": "microsoft-windows-10-22h2",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Applications",
        "DomainSysvol/GPO/Machine/microsoft",
        "DomainSysvol/GPO/Machine/microsoft/windows nt",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 5064,
          "path": "Backup.xml",
          "sha256": "46eddd8ff409e9e6e399d88c0010344ed0f26c7995a59dbf3d916181028d95c6"
        },
        {
          "bytes": 558,
          "path": "DomainSysvol/GPO/User/comment.cmtx",
          "sha256": "1c5513fd13d4affbad4cbc0af300683bd881bdd6da171762360db8b759cebc74"
        },
        {
          "bytes": 436,
          "path": "DomainSysvol/GPO/User/registry.pol",
          "sha256": "4d7e373625f1d959c384377f67858dc590a81bc32b360c4878c8d03afc1524d0"
        },
        {
          "bytes": 591,
          "path": "bkupInfo.xml",
          "sha256": "0d3b58f3cc624d7d4e370efd2f341a2f5822d60087a9a922dee114f67f72951c"
        },
        {
          "bytes": 17972,
          "path": "gpreport.xml",
          "sha256": "520133fbeaf3f03d09d784a616cb688fdfb1bd1292046096b67aba7c57b17f6d"
        }
      ],
      "name": "MSFT Windows 10 22H2 - User",
      "purpose": "MSFTWindows1022H2User",
      "scope": "user",
      "source_backup_path": "Windows-10-v22H2-Security-Baseline/GPOs/{C91CAC2A-3421-404F-A1B6-025301CE3261}",
      "source_display_name": "MSFT Windows 10 22H2 - User",
      "source_gpo_id": "{CEEA5FA1-B180-4C4F-8FA8-FD15C5B9B9BA}",
      "source_options": 2,
      "source_package_name": "Windows 10 version 22H2 Security Baseline.zip",
      "source_package_sha256": "cbda99d18339ed7445566447323bd1da40b3e31ab7a5fdba1dae024517a52e1a",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2010%20version%2022H2%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "fcf3caf4f6f1c7dba51a1bc37f01de12a627edf33f61af14cd8d291d6f07597c.ipmsgpo",
      "artifact_sha256": "fcf3caf4f6f1c7dba51a1bc37f01de12a627edf33f61af14cd8d291d6f07597c",
      "artifact_size": 40325,
      "backup_id": "{CB79185B-5015-497C-8F1E-48E9E3B4ABB6}",
      "baseline_id": "microsoft-windows-10-22h2",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Scripts",
        "DomainSysvol/GPO/Machine/Scripts/Shutdown",
        "DomainSysvol/GPO/Machine/Scripts/Startup",
        "DomainSysvol/GPO/Machine/microsoft",
        "DomainSysvol/GPO/Machine/microsoft/windows nt",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 5792,
          "path": "Backup.xml",
          "sha256": "d318c25af16a9730bcbee20466c53ba044bf78b05ab41fbbb241edcc3a71239c"
        },
        {
          "bytes": 557,
          "path": "DomainSysvol/GPO/Machine/comment.cmtx",
          "sha256": "7e62a37b598c50ae15bb714c96be700b2764f52ef5b1e9ae6e60b8622a5d4613"
        },
        {
          "bytes": 142,
          "path": "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit/GptTmpl.inf",
          "sha256": "07cba636ed9c1c30c4a4c228e555151f1fc43f7bfc941cbb221ed67297ea3dbc"
        },
        {
          "bytes": 1862,
          "path": "DomainSysvol/GPO/Machine/registry.pol",
          "sha256": "67c1f37f8c22e56c476b39b30b3060d0b69afe7a88fc66bda3557260632d87c2"
        },
        {
          "bytes": 596,
          "path": "bkupInfo.xml",
          "sha256": "6ef223e0782577589718daf48f5ffbed84b9cb091e38a86d42516dd1c44dfd59"
        },
        {
          "bytes": 31340,
          "path": "gpreport.xml",
          "sha256": "48279c70393eac36f382a9c4d607bab7be1c66c4db2c7c6def73162272014868"
        }
      ],
      "name": "MSFT Windows 10 22H2 - BitLocker",
      "purpose": "MSFTWindows1022H2BitLocker",
      "scope": "machine",
      "source_backup_path": "Windows-10-v22H2-Security-Baseline/GPOs/{CB79185B-5015-497C-8F1E-48E9E3B4ABB6}",
      "source_display_name": "MSFT Windows 10 22H2 - BitLocker",
      "source_gpo_id": "{38F3407D-666B-4E65-BCAF-D50CFC8BD500}",
      "source_options": 1,
      "source_package_name": "Windows 10 version 22H2 Security Baseline.zip",
      "source_package_sha256": "cbda99d18339ed7445566447323bd1da40b3e31ab7a5fdba1dae024517a52e1a",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2010%20version%2022H2%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "21348a43fe7d9988f9e703aa9be82fe5cb4890870b82a7ab8bbb042b79670278.ipmsgpo",
      "artifact_sha256": "21348a43fe7d9988f9e703aa9be82fe5cb4890870b82a7ab8bbb042b79670278",
      "artifact_size": 41083,
      "backup_id": "{39B711D6-ACD3-42D7-BA55-47CBD4D3B1C7}",
      "baseline_id": "microsoft-windows-11-23h2",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Scripts",
        "DomainSysvol/GPO/Machine/Scripts/Shutdown",
        "DomainSysvol/GPO/Machine/Scripts/Startup",
        "DomainSysvol/GPO/Machine/microsoft",
        "DomainSysvol/GPO/Machine/microsoft/windows nt",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 5792,
          "path": "Backup.xml",
          "sha256": "a25a52bce0bd95b89ea0252a605c4d1826dc05260980549d5aa81b6e06d01bf9"
        },
        {
          "bytes": 557,
          "path": "DomainSysvol/GPO/Machine/comment.cmtx",
          "sha256": "7e62a37b598c50ae15bb714c96be700b2764f52ef5b1e9ae6e60b8622a5d4613"
        },
        {
          "bytes": 142,
          "path": "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit/GptTmpl.inf",
          "sha256": "07cba636ed9c1c30c4a4c228e555151f1fc43f7bfc941cbb221ed67297ea3dbc"
        },
        {
          "bytes": 1862,
          "path": "DomainSysvol/GPO/Machine/registry.pol",
          "sha256": "67c1f37f8c22e56c476b39b30b3060d0b69afe7a88fc66bda3557260632d87c2"
        },
        {
          "bytes": 596,
          "path": "bkupInfo.xml",
          "sha256": "f853a4f3f8212b78031ca866b1573487381cb15a40a033abd1543df51f6f6334"
        },
        {
          "bytes": 32098,
          "path": "gpreport.xml",
          "sha256": "a9212015ad80c5bf0922508ce930ad0c9c0d04fe451e7af0061ee51a04cc0c92"
        }
      ],
      "name": "MSFT Windows 11 23H2 - BitLocker",
      "purpose": "MSFTWindows1123H2BitLocker",
      "scope": "machine",
      "source_backup_path": "Windows 11 v23H2 Security Baseline/GPOs/{39B711D6-ACD3-42D7-BA55-47CBD4D3B1C7}",
      "source_display_name": "MSFT Windows 11 23H2 - BitLocker",
      "source_gpo_id": "{F9CA6C42-3A57-4D81-88BF-6CD8289FD1F5}",
      "source_options": 1,
      "source_package_name": "Windows 11 v23H2 Security Baseline.zip",
      "source_package_sha256": "2e3a61d0245c16bea51a9ee78cbf0793c88046901cecc0039db0dc84fae7d7b7",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2011%20v23H2%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "2ec423fc78271e1e52c6c688ee4ffdbb95c464705ccbaba7c0894b69c8602016.ipmsgpo",
      "artifact_sha256": "2ec423fc78271e1e52c6c688ee4ffdbb95c464705ccbaba7c0894b69c8602016",
      "artifact_size": 354302,
      "backup_id": "{72D4230C-5BFB-497D-BC14-67F7E18F2954}",
      "baseline_id": "microsoft-windows-11-23h2",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Applications",
        "DomainSysvol/GPO/Machine/Scripts",
        "DomainSysvol/GPO/Machine/Scripts/Shutdown",
        "DomainSysvol/GPO/Machine/Scripts/Startup",
        "DomainSysvol/GPO/Machine/microsoft",
        "DomainSysvol/GPO/Machine/microsoft/windows nt",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 6149,
          "path": "Backup.xml",
          "sha256": "e51963b47fbe138a71cd4548497f028d7c34493bd5337e9d8b4a88aa4f7a9b52"
        },
        {
          "bytes": 555,
          "path": "DomainSysvol/GPO/Machine/comment.cmtx",
          "sha256": "e6d7b0805b21144958f6b70b5273bd3eab96950b59fbcb1654654f4924cbd35c"
        },
        {
          "bytes": 142,
          "path": "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit/GptTmpl.inf",
          "sha256": "07cba636ed9c1c30c4a4c228e555151f1fc43f7bfc941cbb221ed67297ea3dbc"
        },
        {
          "bytes": 25970,
          "path": "DomainSysvol/GPO/Machine/registry.pol",
          "sha256": "8a5b1628731d7516b4d45144cef6c9aab6e823b62bcd4db226e83c5820e088cc"
        },
        {
          "bytes": 600,
          "path": "bkupInfo.xml",
          "sha256": "d7c0ee6ec61f8547ba45dc36998bdf607dcd9ad535ced5d234de40725fe44647"
        },
        {
          "bytes": 320850,
          "path": "gpreport.xml",
          "sha256": "9314812a7482e95ac21cfdc6a7d7a1a4057b97e07f7d4124f78822ab6ae95d85"
        }
      ],
      "name": "MSFT Internet Explorer 11 - Computer",
      "purpose": "MSFTInternetExplorer11Computer",
      "scope": "machine",
      "source_backup_path": "Windows 11 v23H2 Security Baseline/GPOs/{72D4230C-5BFB-497D-BC14-67F7E18F2954}",
      "source_display_name": "MSFT Internet Explorer 11 - Computer",
      "source_gpo_id": "{D5398278-ABE5-4648-921E-D68A15AF59E9}",
      "source_options": 1,
      "source_package_name": "Windows 11 v23H2 Security Baseline.zip",
      "source_package_sha256": "2e3a61d0245c16bea51a9ee78cbf0793c88046901cecc0039db0dc84fae7d7b7",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2011%20v23H2%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "0c67a6d26e308e10ecfd8fb4a8c19ecf88f2ddc0b5e5704cd643046724687d1c.ipmsgpo",
      "artifact_sha256": "0c67a6d26e308e10ecfd8fb4a8c19ecf88f2ddc0b5e5704cd643046724687d1c",
      "artifact_size": 25413,
      "backup_id": "{7AFCEE57-FD46-4225-94E7-A80DD57D1A31}",
      "baseline_id": "microsoft-windows-11-23h2",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Applications",
        "DomainSysvol/GPO/Machine/microsoft",
        "DomainSysvol/GPO/Machine/microsoft/windows nt",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 5064,
          "path": "Backup.xml",
          "sha256": "ef28f9d7875d6b14edab8d9d06f8403fab97a8b0d119dd90f08c3e1e922affde"
        },
        {
          "bytes": 558,
          "path": "DomainSysvol/GPO/User/comment.cmtx",
          "sha256": "1c5513fd13d4affbad4cbc0af300683bd881bdd6da171762360db8b759cebc74"
        },
        {
          "bytes": 436,
          "path": "DomainSysvol/GPO/User/registry.pol",
          "sha256": "4d7e373625f1d959c384377f67858dc590a81bc32b360c4878c8d03afc1524d0"
        },
        {
          "bytes": 591,
          "path": "bkupInfo.xml",
          "sha256": "feef54e2165521fc1b325eb6793eb4737c41ed20b297c33cab38d7d2a02e7775"
        },
        {
          "bytes": 18732,
          "path": "gpreport.xml",
          "sha256": "982d081df1cb86ba5e9b17bf876d51cee44d57f4db00a7982deb71ddb796766a"
        }
      ],
      "name": "MSFT Windows 11 23H2 - User",
      "purpose": "MSFTWindows1123H2User",
      "scope": "user",
      "source_backup_path": "Windows 11 v23H2 Security Baseline/GPOs/{7AFCEE57-FD46-4225-94E7-A80DD57D1A31}",
      "source_display_name": "MSFT Windows 11 23H2 - User",
      "source_gpo_id": "{83A5E982-986A-4447-A8A1-7945B71C18B3}",
      "source_options": 2,
      "source_package_name": "Windows 11 v23H2 Security Baseline.zip",
      "source_package_sha256": "2e3a61d0245c16bea51a9ee78cbf0793c88046901cecc0039db0dc84fae7d7b7",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2011%20v23H2%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "43ebd1999b4504ecedf85895f7f68d3a5ca69e7ba559432f0ae10f66ccd23d53.ipmsgpo",
      "artifact_sha256": "43ebd1999b4504ecedf85895f7f68d3a5ca69e7ba559432f0ae10f66ccd23d53",
      "artifact_size": 335151,
      "backup_id": "{9E9FAF7E-9ED1-4B19-8F5F-65A37ACD39AF}",
      "baseline_id": "microsoft-windows-11-23h2",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Applications",
        "DomainSysvol/GPO/Machine/Scripts",
        "DomainSysvol/GPO/Machine/Scripts/Shutdown",
        "DomainSysvol/GPO/Machine/Scripts/Startup",
        "DomainSysvol/GPO/Machine/microsoft",
        "DomainSysvol/GPO/Machine/microsoft/windows nt",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 8157,
          "path": "Backup.xml",
          "sha256": "896e997999ec559aed635489802db9173b65b5575e7f05d74cb51395db301629"
        },
        {
          "bytes": 543,
          "path": "DomainSysvol/GPO/Machine/comment.cmtx",
          "sha256": "4b7db4343c391731d4ef2eb302bcd13b301537e29cbb28f1371119504ab7d9ee"
        },
        {
          "bytes": 2196,
          "path": "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit/audit.csv",
          "sha256": "87be5144cf18bee60549cd169ee63542c65a7a92daf8358e56010302654add75"
        },
        {
          "bytes": 7346,
          "path": "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit/GptTmpl.inf",
          "sha256": "7965a2d21d80ec55d1555b8b64258c45e4b51290ceaa98bc3d8fdab51adc2554"
        },
        {
          "bytes": 20068,
          "path": "DomainSysvol/GPO/Machine/registry.pol",
          "sha256": "7277b327a94920a11f0a58cca98fb7c72e7d1f34264e71b7dc29bf184b1a6fd2"
        },
        {
          "bytes": 595,
          "path": "bkupInfo.xml",
          "sha256": "68687abd1471869086f635d457b9e12ec7d95c998f4d15324593e71129499c48"
        },
        {
          "bytes": 296206,
          "path": "gpreport.xml",
          "sha256": "c94fd232b2d0e2115ea60f8d215c0c25d1be62dc4161754a34187b4992ec33f2"
        }
      ],
      "name": "MSFT Windows 11 23H2 - Computer",
      "purpose": "MSFTWindows1123H2Computer",
      "scope": "machine",
      "source_backup_path": "Windows 11 v23H2 Security Baseline/GPOs/{9E9FAF7E-9ED1-4B19-8F5F-65A37ACD39AF}",
      "source_display_name": "MSFT Windows 11 23H2 - Computer",
      "source_gpo_id": "{1B6AAB4D-20DC-4956-9439-DD15694E2B6A}",
      "source_options": 1,
      "source_package_name": "Windows 11 v23H2 Security Baseline.zip",
      "source_package_sha256": "2e3a61d0245c16bea51a9ee78cbf0793c88046901cecc0039db0dc84fae7d7b7",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2011%20v23H2%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "bf6ddfffee665516fcadbcaa8d0eadeb9bcf07ec88617ec47c078185975c04ce.ipmsgpo",
      "artifact_sha256": "bf6ddfffee665516fcadbcaa8d0eadeb9bcf07ec88617ec47c078185975c04ce",
      "artifact_size": 37933,
      "backup_id": "{A484ECC9-232E-44F0-BEF6-05BC7231727A}",
      "baseline_id": "microsoft-windows-11-23h2",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Scripts",
        "DomainSysvol/GPO/Machine/Scripts/Shutdown",
        "DomainSysvol/GPO/Machine/Scripts/Startup",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 4453,
          "path": "Backup.xml",
          "sha256": "518ba713fce76e54562772cfa6452cc7cd7d1a38f0f36a08d80b6d577b289112"
        },
        {
          "bytes": 549,
          "path": "DomainSysvol/GPO/Machine/comment.cmtx",
          "sha256": "94f49ee096c38f34ddf86a3d864661da5a39cca6a641ce5db6c159bf106d8e01"
        },
        {
          "bytes": 1222,
          "path": "DomainSysvol/GPO/Machine/registry.pol",
          "sha256": "24c0047b59cfed4d694ff20bbf2ba40a8c2c12bb230865c29cbf49e0f710c423"
        },
        {
          "bytes": 603,
          "path": "bkupInfo.xml",
          "sha256": "d8042df90f952954bc6daff9bd1e5f30f50282f0fb6dfbfdb5c2cbb30b60254e"
        },
        {
          "bytes": 31074,
          "path": "gpreport.xml",
          "sha256": "c21e3ec30843a51a44117b395e3c66598221970dcd4bed377aa79bf71e8109f8"
        }
      ],
      "name": "MSFT Windows 11 23H2 - Credential Guard",
      "purpose": "MSFTWindows1123H2CredentialGuard",
      "scope": "machine",
      "source_backup_path": "Windows 11 v23H2 Security Baseline/GPOs/{A484ECC9-232E-44F0-BEF6-05BC7231727A}",
      "source_display_name": "MSFT Windows 11 23H2 - Credential Guard",
      "source_gpo_id": "{3459AD93-6648-423E-9777-0C82975217D5}",
      "source_options": 1,
      "source_package_name": "Windows 11 v23H2 Security Baseline.zip",
      "source_package_sha256": "2e3a61d0245c16bea51a9ee78cbf0793c88046901cecc0039db0dc84fae7d7b7",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2011%20v23H2%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "dc13f374615e3c168031b3d70e999222970ccfee3bec789a977e1410e5d2eb47.ipmsgpo",
      "artifact_sha256": "dc13f374615e3c168031b3d70e999222970ccfee3bec789a977e1410e5d2eb47",
      "artifact_size": 25439,
      "backup_id": "{A4EA0481-872A-4286-839D-A64FFC8F521B}",
      "baseline_id": "microsoft-windows-11-23h2",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Applications",
        "DomainSysvol/GPO/Machine/Scripts",
        "DomainSysvol/GPO/Machine/Scripts/Shutdown",
        "DomainSysvol/GPO/Machine/Scripts/Startup",
        "DomainSysvol/GPO/Machine/microsoft",
        "DomainSysvol/GPO/Machine/microsoft/windows nt",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 5761,
          "path": "Backup.xml",
          "sha256": "acbebf7e442902856acc5df968ed96ee9051e7044eb18fa8a28c5f099b6a90d2"
        },
        {
          "bytes": 614,
          "path": "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit/GptTmpl.inf",
          "sha256": "68bff0f76db5c82f3a3db00611190bd792c47d758750b507232bd6d8b17820df"
        },
        {
          "bytes": 602,
          "path": "bkupInfo.xml",
          "sha256": "77265c29fe17bc8034886619873c7d9a900d673497f1afe3aa1840d78ea4db92"
        },
        {
          "bytes": 18434,
          "path": "gpreport.xml",
          "sha256": "09ac810f7694e9e799dfbd9091fe819d453fa1348aa138efe71b57a22e6465e8"
        }
      ],
      "name": "MSFT Windows 11 23H2 - Domain Security",
      "purpose": "MSFTWindows1123H2DomainSecurity",
      "scope": "domain",
      "source_backup_path": "Windows 11 v23H2 Security Baseline/GPOs/{A4EA0481-872A-4286-839D-A64FFC8F521B}",
      "source_display_name": "MSFT Windows 11 23H2 - Domain Security",
      "source_gpo_id": "{E9F1D4BF-D7C0-4358-B1CD-6B1F7E1754D3}",
      "source_options": 1,
      "source_package_name": "Windows 11 v23H2 Security Baseline.zip",
      "source_package_sha256": "2e3a61d0245c16bea51a9ee78cbf0793c88046901cecc0039db0dc84fae7d7b7",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2011%20v23H2%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "ca6c1aa52d41bbf7aad68afbccc208eaa119f24e819382c944738362b1858cb4.ipmsgpo",
      "artifact_sha256": "ca6c1aa52d41bbf7aad68afbccc208eaa119f24e819382c944738362b1858cb4",
      "artifact_size": 25490,
      "backup_id": "{A59C7553-3449-43AD-929F-368ABC4B3EDF}",
      "baseline_id": "microsoft-windows-11-23h2",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Applications",
        "DomainSysvol/GPO/Machine/microsoft",
        "DomainSysvol/GPO/Machine/microsoft/windows nt",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 5069,
          "path": "Backup.xml",
          "sha256": "7ed7aaeb86a374475dd3fa72bf8ddb8801bcb01419fd2550b4189d2ff249c852"
        },
        {
          "bytes": 901,
          "path": "DomainSysvol/GPO/User/comment.cmtx",
          "sha256": "4626e59f12f72f994ce0a1591e5fbcfb1c83cc60462c35d3dff42f745cb0ea30"
        },
        {
          "bytes": 534,
          "path": "DomainSysvol/GPO/User/registry.pol",
          "sha256": "bdc7178487ef6346e2e4796ac6aae54a2076f950cb541bb4bd88c7c4a6874a96"
        },
        {
          "bytes": 596,
          "path": "bkupInfo.xml",
          "sha256": "14d04fac3b61d32fe8ddea281eef41a9b28b12d8a09802b272b27e53ce020c4b"
        },
        {
          "bytes": 18358,
          "path": "gpreport.xml",
          "sha256": "739157dc1ba1cf545c1f51ee59b8c4289c29636eb912f38cab41f3f152552d34"
        }
      ],
      "name": "MSFT Internet Explorer 11 - User",
      "purpose": "MSFTInternetExplorer11User",
      "scope": "user",
      "source_backup_path": "Windows 11 v23H2 Security Baseline/GPOs/{A59C7553-3449-43AD-929F-368ABC4B3EDF}",
      "source_display_name": "MSFT Internet Explorer 11 - User",
      "source_gpo_id": "{582D31BD-8974-43C8-B88B-FC18B4254E87}",
      "source_options": 2,
      "source_package_name": "Windows 11 v23H2 Security Baseline.zip",
      "source_package_sha256": "2e3a61d0245c16bea51a9ee78cbf0793c88046901cecc0039db0dc84fae7d7b7",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2011%20v23H2%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "a2ca73c23bd97b027e150ebdd56816fe5dad7b32a7ff0030f19c69a04803c9cf.ipmsgpo",
      "artifact_sha256": "a2ca73c23bd97b027e150ebdd56816fe5dad7b32a7ff0030f19c69a04803c9cf",
      "artifact_size": 89147,
      "backup_id": "{D0E7DD4A-C681-488D-995A-0F061575BCE3}",
      "baseline_id": "microsoft-windows-11-23h2",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 3616,
          "path": "Backup.xml",
          "sha256": "9af853db54a7bedf3d1c8d21d9cd43fa462d5d6422fe61c4086aa4662b14b3b5"
        },
        {
          "bytes": 554,
          "path": "DomainSysvol/GPO/Machine/comment.cmtx",
          "sha256": "f4cb5d64e7a8cec20da34b276020efb31262ab81bc325d754578d60f87d5e387"
        },
        {
          "bytes": 8040,
          "path": "DomainSysvol/GPO/Machine/registry.pol",
          "sha256": "bdf7dcab509ec512059b1865a294eb8b242e805a50f622db7fdc354dfb90f700"
        },
        {
          "bytes": 605,
          "path": "bkupInfo.xml",
          "sha256": "26050c1836610e403624981e391022169e108a2dcac2d644ee43491d2cfa3051"
        },
        {
          "bytes": 76300,
          "path": "gpreport.xml",
          "sha256": "6aa9b93cfabd821147ff79c943e317efe8863e653fc565104da46ca2aea7ee4e"
        }
      ],
      "name": "MSFT Windows 11 23H2 - Defender Antivirus",
      "purpose": "MSFTWindows1123H2DefenderAntivirus",
      "scope": "machine",
      "source_backup_path": "Windows 11 v23H2 Security Baseline/GPOs/{D0E7DD4A-C681-488D-995A-0F061575BCE3}",
      "source_display_name": "MSFT Windows 11 23H2 - Defender Antivirus",
      "source_gpo_id": "{048EDF92-475E-4360-A38B-025342E2D833}",
      "source_options": 1,
      "source_package_name": "Windows 11 v23H2 Security Baseline.zip",
      "source_package_sha256": "2e3a61d0245c16bea51a9ee78cbf0793c88046901cecc0039db0dc84fae7d7b7",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2011%20v23H2%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "33d705263931af62f0e7f91f3470ad4f651bafedd41e3377f8928ef5e2a3d258.ipmsgpo",
      "artifact_sha256": "33d705263931af62f0e7f91f3470ad4f651bafedd41e3377f8928ef5e2a3d258",
      "artifact_size": 25439,
      "backup_id": "{04602802-38C4-4900-87CD-B126DA8875ED}",
      "baseline_id": "microsoft-windows-11-24h2",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Applications",
        "DomainSysvol/GPO/Machine/Scripts",
        "DomainSysvol/GPO/Machine/Scripts/Shutdown",
        "DomainSysvol/GPO/Machine/Scripts/Startup",
        "DomainSysvol/GPO/Machine/microsoft",
        "DomainSysvol/GPO/Machine/microsoft/windows nt",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 5761,
          "path": "Backup.xml",
          "sha256": "542d61afad315fe29e0888887fd054e3d448c6acfe0090d1980cdf00fb2a2397"
        },
        {
          "bytes": 614,
          "path": "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit/GptTmpl.inf",
          "sha256": "68bff0f76db5c82f3a3db00611190bd792c47d758750b507232bd6d8b17820df"
        },
        {
          "bytes": 602,
          "path": "bkupInfo.xml",
          "sha256": "ba6a6969ca2c8bc07eb7810fd4ef1cef76fa6ff9bed2225c235e9bd12993480a"
        },
        {
          "bytes": 18434,
          "path": "gpreport.xml",
          "sha256": "d6df5596add7c15e01925d7aca626758789f52dbfe22375d2db2603435f4e5c8"
        }
      ],
      "name": "MSFT Windows 11 24H2 - Domain Security",
      "purpose": "MSFTWindows1124H2DomainSecurity",
      "scope": "domain",
      "source_backup_path": "Windows 11 v24H2 Security Baseline/GPOs/{04602802-38C4-4900-87CD-B126DA8875ED}",
      "source_display_name": "MSFT Windows 11 24H2 - Domain Security",
      "source_gpo_id": "{E9F1D4BF-D7C0-4358-B1CD-6B1F7E1754D3}",
      "source_options": 1,
      "source_package_name": "Windows 11 v24H2 Security Baseline.zip",
      "source_package_sha256": "b75439a231c64edaccaad16a16268d199f56ce78273104e117d893f82cf174a5",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2011%20v24H2%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "1c3e40e6436366a1db7bee2e15b3e7b049d5b4aa9c87dc6067d6d062f7221eb5.ipmsgpo",
      "artifact_sha256": "1c3e40e6436366a1db7bee2e15b3e7b049d5b4aa9c87dc6067d6d062f7221eb5",
      "artifact_size": 42027,
      "backup_id": "{3C4158A9-6823-4577-8AAE-197181A6E6AD}",
      "baseline_id": "microsoft-windows-11-24h2",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Scripts",
        "DomainSysvol/GPO/Machine/Scripts/Shutdown",
        "DomainSysvol/GPO/Machine/Scripts/Startup",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 4453,
          "path": "Backup.xml",
          "sha256": "28e72fea1ce448041cdf1bb12267a7f80574cbbef8e20bcf46711298dfae6e09"
        },
        {
          "bytes": 549,
          "path": "DomainSysvol/GPO/Machine/comment.cmtx",
          "sha256": "94f49ee096c38f34ddf86a3d864661da5a39cca6a641ce5db6c159bf106d8e01"
        },
        {
          "bytes": 1392,
          "path": "DomainSysvol/GPO/Machine/registry.pol",
          "sha256": "abb45d64d366833f5fb6901a54586c9f49123a4e4284d0906bd03d5a688354ec"
        },
        {
          "bytes": 603,
          "path": "bkupInfo.xml",
          "sha256": "7b007f997c99a38af888812198218f2f5717d24ee37e6384338065fc259103c3"
        },
        {
          "bytes": 34998,
          "path": "gpreport.xml",
          "sha256": "88d60eed0bf0ad1a13a2a9a2ab7280dacb3841e27052e89a1d7f0afec93b3136"
        }
      ],
      "name": "MSFT Windows 11 24H2 - Credential Guard",
      "purpose": "MSFTWindows1124H2CredentialGuard",
      "scope": "machine",
      "source_backup_path": "Windows 11 v24H2 Security Baseline/GPOs/{3C4158A9-6823-4577-8AAE-197181A6E6AD}",
      "source_display_name": "MSFT Windows 11 24H2 - Credential Guard",
      "source_gpo_id": "{3459AD93-6648-423E-9777-0C82975217D5}",
      "source_options": 1,
      "source_package_name": "Windows 11 v24H2 Security Baseline.zip",
      "source_package_sha256": "b75439a231c64edaccaad16a16268d199f56ce78273104e117d893f82cf174a5",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2011%20v24H2%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "3e778e43f39c71e0ad650ae62fbb12abbc0566bc0b4089a789b59e9680101ab7.ipmsgpo",
      "artifact_sha256": "3e778e43f39c71e0ad650ae62fbb12abbc0566bc0b4089a789b59e9680101ab7",
      "artifact_size": 41085,
      "backup_id": "{9DD51389-33D0-4D19-8274-F9C19C54AACB}",
      "baseline_id": "microsoft-windows-11-24h2",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Scripts",
        "DomainSysvol/GPO/Machine/Scripts/Shutdown",
        "DomainSysvol/GPO/Machine/Scripts/Startup",
        "DomainSysvol/GPO/Machine/microsoft",
        "DomainSysvol/GPO/Machine/microsoft/windows nt",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 5792,
          "path": "Backup.xml",
          "sha256": "cd8484530df141729f44598a1cadad06c41f0b470e6a8be447a41fc7967c0c08"
        },
        {
          "bytes": 557,
          "path": "DomainSysvol/GPO/Machine/comment.cmtx",
          "sha256": "7e62a37b598c50ae15bb714c96be700b2764f52ef5b1e9ae6e60b8622a5d4613"
        },
        {
          "bytes": 142,
          "path": "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit/GptTmpl.inf",
          "sha256": "07cba636ed9c1c30c4a4c228e555151f1fc43f7bfc941cbb221ed67297ea3dbc"
        },
        {
          "bytes": 1862,
          "path": "DomainSysvol/GPO/Machine/registry.pol",
          "sha256": "67c1f37f8c22e56c476b39b30b3060d0b69afe7a88fc66bda3557260632d87c2"
        },
        {
          "bytes": 596,
          "path": "bkupInfo.xml",
          "sha256": "d57136c35a1872f1f95a05ee1270a9476bf71904e288170373e75e3302e7da69"
        },
        {
          "bytes": 32100,
          "path": "gpreport.xml",
          "sha256": "62df93e0d116a36ccb09d3006f7059264e8646ef64cad471a65aa52b2c78404f"
        }
      ],
      "name": "MSFT Windows 11 24H2 - BitLocker",
      "purpose": "MSFTWindows1124H2BitLocker",
      "scope": "machine",
      "source_backup_path": "Windows 11 v24H2 Security Baseline/GPOs/{9DD51389-33D0-4D19-8274-F9C19C54AACB}",
      "source_display_name": "MSFT Windows 11 24H2 - BitLocker",
      "source_gpo_id": "{F9CA6C42-3A57-4D81-88BF-6CD8289FD1F5}",
      "source_options": 1,
      "source_package_name": "Windows 11 v24H2 Security Baseline.zip",
      "source_package_sha256": "b75439a231c64edaccaad16a16268d199f56ce78273104e117d893f82cf174a5",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2011%20v24H2%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "92f0bcfd871746b89081b521b3410edf73408feb0e43b85bcd19b93a889e1e2c.ipmsgpo",
      "artifact_sha256": "92f0bcfd871746b89081b521b3410edf73408feb0e43b85bcd19b93a889e1e2c",
      "artifact_size": 354302,
      "backup_id": "{BB10D67B-FBEA-4CD0-8E5F-09AC67C07670}",
      "baseline_id": "microsoft-windows-11-24h2",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Applications",
        "DomainSysvol/GPO/Machine/Scripts",
        "DomainSysvol/GPO/Machine/Scripts/Shutdown",
        "DomainSysvol/GPO/Machine/Scripts/Startup",
        "DomainSysvol/GPO/Machine/microsoft",
        "DomainSysvol/GPO/Machine/microsoft/windows nt",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 6149,
          "path": "Backup.xml",
          "sha256": "e51963b47fbe138a71cd4548497f028d7c34493bd5337e9d8b4a88aa4f7a9b52"
        },
        {
          "bytes": 555,
          "path": "DomainSysvol/GPO/Machine/comment.cmtx",
          "sha256": "e6d7b0805b21144958f6b70b5273bd3eab96950b59fbcb1654654f4924cbd35c"
        },
        {
          "bytes": 142,
          "path": "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit/GptTmpl.inf",
          "sha256": "07cba636ed9c1c30c4a4c228e555151f1fc43f7bfc941cbb221ed67297ea3dbc"
        },
        {
          "bytes": 25970,
          "path": "DomainSysvol/GPO/Machine/registry.pol",
          "sha256": "8a5b1628731d7516b4d45144cef6c9aab6e823b62bcd4db226e83c5820e088cc"
        },
        {
          "bytes": 600,
          "path": "bkupInfo.xml",
          "sha256": "f995299f9984c642e89c5f05baf2a82e7f617ec7a992101313325d5f15cb926b"
        },
        {
          "bytes": 320850,
          "path": "gpreport.xml",
          "sha256": "13d0a8917e0dee455cac01e3055eb24b4ce3cd848a382271d58ae20cfd89ea45"
        }
      ],
      "name": "MSFT Internet Explorer 11 - Computer",
      "purpose": "MSFTInternetExplorer11Computer",
      "scope": "machine",
      "source_backup_path": "Windows 11 v24H2 Security Baseline/GPOs/{BB10D67B-FBEA-4CD0-8E5F-09AC67C07670}",
      "source_display_name": "MSFT Internet Explorer 11 - Computer",
      "source_gpo_id": "{D5398278-ABE5-4648-921E-D68A15AF59E9}",
      "source_options": 1,
      "source_package_name": "Windows 11 v24H2 Security Baseline.zip",
      "source_package_sha256": "b75439a231c64edaccaad16a16268d199f56ce78273104e117d893f82cf174a5",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2011%20v24H2%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "1490a4cdecc50dde16c3390a436b474004c9b5ea5980bb71e29e6a6d22b709f6.ipmsgpo",
      "artifact_sha256": "1490a4cdecc50dde16c3390a436b474004c9b5ea5980bb71e29e6a6d22b709f6",
      "artifact_size": 25490,
      "backup_id": "{BF76B495-48DD-4A15-AFFF-E9E20A6C9AAB}",
      "baseline_id": "microsoft-windows-11-24h2",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Applications",
        "DomainSysvol/GPO/Machine/microsoft",
        "DomainSysvol/GPO/Machine/microsoft/windows nt",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 5069,
          "path": "Backup.xml",
          "sha256": "7ed7aaeb86a374475dd3fa72bf8ddb8801bcb01419fd2550b4189d2ff249c852"
        },
        {
          "bytes": 901,
          "path": "DomainSysvol/GPO/User/comment.cmtx",
          "sha256": "4626e59f12f72f994ce0a1591e5fbcfb1c83cc60462c35d3dff42f745cb0ea30"
        },
        {
          "bytes": 534,
          "path": "DomainSysvol/GPO/User/registry.pol",
          "sha256": "bdc7178487ef6346e2e4796ac6aae54a2076f950cb541bb4bd88c7c4a6874a96"
        },
        {
          "bytes": 596,
          "path": "bkupInfo.xml",
          "sha256": "afd269e6cef1e581782715c1cffdaea4862d32c8a474d4f450b46f10702bc2de"
        },
        {
          "bytes": 18358,
          "path": "gpreport.xml",
          "sha256": "8d0b55fe077871a20740dbff03e5cca28a0ef3a5fdfc5bd868e6b5062f28e95d"
        }
      ],
      "name": "MSFT Internet Explorer 11 - User",
      "purpose": "MSFTInternetExplorer11User",
      "scope": "user",
      "source_backup_path": "Windows 11 v24H2 Security Baseline/GPOs/{BF76B495-48DD-4A15-AFFF-E9E20A6C9AAB}",
      "source_display_name": "MSFT Internet Explorer 11 - User",
      "source_gpo_id": "{582D31BD-8974-43C8-B88B-FC18B4254E87}",
      "source_options": 2,
      "source_package_name": "Windows 11 v24H2 Security Baseline.zip",
      "source_package_sha256": "b75439a231c64edaccaad16a16268d199f56ce78273104e117d893f82cf174a5",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2011%20v24H2%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "3526abf0d87a605f059214d95781e45f45132e92451f0c78374505199ea3e56b.ipmsgpo",
      "artifact_sha256": "3526abf0d87a605f059214d95781e45f45132e92451f0c78374505199ea3e56b",
      "artifact_size": 25409,
      "backup_id": "{C4FCE0A9-BC29-4589-A63D-144E8CD991CE}",
      "baseline_id": "microsoft-windows-11-24h2",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Applications",
        "DomainSysvol/GPO/Machine/microsoft",
        "DomainSysvol/GPO/Machine/microsoft/windows nt",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 5065,
          "path": "Backup.xml",
          "sha256": "c64acca7fd25fc5715f7da017f798fb571f411c25a93e067252a6020d6c2d1b5"
        },
        {
          "bytes": 553,
          "path": "DomainSysvol/GPO/User/comment.cmtx",
          "sha256": "12586d4ccf801507d2dac5c72d688d1bca3c76f97af5d45422feefdcc2437796"
        },
        {
          "bytes": 436,
          "path": "DomainSysvol/GPO/User/registry.pol",
          "sha256": "4d7e373625f1d959c384377f67858dc590a81bc32b360c4878c8d03afc1524d0"
        },
        {
          "bytes": 591,
          "path": "bkupInfo.xml",
          "sha256": "2576337f3f6117a83e10fcc1c78ff870b708a622bc8f2e9d71f2fa78498ca9fe"
        },
        {
          "bytes": 18732,
          "path": "gpreport.xml",
          "sha256": "cfc99c7c11de383e1a4564b76bf83600325734f4a0af45bb7da73c5f328d82f8"
        }
      ],
      "name": "MSFT Windows 11 24H2 - User",
      "purpose": "MSFTWindows1124H2User",
      "scope": "user",
      "source_backup_path": "Windows 11 v24H2 Security Baseline/GPOs/{C4FCE0A9-BC29-4589-A63D-144E8CD991CE}",
      "source_display_name": "MSFT Windows 11 24H2 - User",
      "source_gpo_id": "{83A5E982-986A-4447-A8A1-7945B71C18B3}",
      "source_options": 2,
      "source_package_name": "Windows 11 v24H2 Security Baseline.zip",
      "source_package_sha256": "b75439a231c64edaccaad16a16268d199f56ce78273104e117d893f82cf174a5",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2011%20v24H2%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "18035bb6fec8c6e883cc638a6e89a1aebc52dbaf46854c846414add553bd7dc3.ipmsgpo",
      "artifact_sha256": "18035bb6fec8c6e883cc638a6e89a1aebc52dbaf46854c846414add553bd7dc3",
      "artifact_size": 378520,
      "backup_id": "{DAD42DA1-8499-42FE-A1CD-9E39196D8B98}",
      "baseline_id": "microsoft-windows-11-24h2",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Applications",
        "DomainSysvol/GPO/Machine/Scripts",
        "DomainSysvol/GPO/Machine/Scripts/Shutdown",
        "DomainSysvol/GPO/Machine/Scripts/Startup",
        "DomainSysvol/GPO/Machine/microsoft",
        "DomainSysvol/GPO/Machine/microsoft/windows nt",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 8157,
          "path": "Backup.xml",
          "sha256": "94efb9c7a700708dd797129fa821607d572ef06fd43235ddf19d9474847f93af"
        },
        {
          "bytes": 556,
          "path": "DomainSysvol/GPO/Machine/comment.cmtx",
          "sha256": "2a5cd0c7a79ef15552a0c2675cd70563088756e3a1abf7da19822adb08ab2669"
        },
        {
          "bytes": 2196,
          "path": "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit/audit.csv",
          "sha256": "87be5144cf18bee60549cd169ee63542c65a7a92daf8358e56010302654add75"
        },
        {
          "bytes": 7926,
          "path": "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit/GptTmpl.inf",
          "sha256": "2da1ec458c2daf9fcf9bd6a56c485a975261e7c04fd59f321000bcae532c75a1"
        },
        {
          "bytes": 24720,
          "path": "DomainSysvol/GPO/Machine/registry.pol",
          "sha256": "fe393f68aa413ea3e59ae400f48f7ec9dd057476894f71d88f7141171cc232a2"
        },
        {
          "bytes": 595,
          "path": "bkupInfo.xml",
          "sha256": "08aa2aef8d482b63c4af3abd9522e2cb17dd1f41a812c2b5f8782eeab5eb98ec"
        },
        {
          "bytes": 334330,
          "path": "gpreport.xml",
          "sha256": "213b45118fbd297bd718d10f8e077d3d0613553b4b49febb7de7b1cd5426a22e"
        }
      ],
      "name": "MSFT Windows 11 24H2 - Computer",
      "purpose": "MSFTWindows1124H2Computer",
      "scope": "machine",
      "source_backup_path": "Windows 11 v24H2 Security Baseline/GPOs/{DAD42DA1-8499-42FE-A1CD-9E39196D8B98}",
      "source_display_name": "MSFT Windows 11 24H2 - Computer",
      "source_gpo_id": "{1B6AAB4D-20DC-4956-9439-DD15694E2B6A}",
      "source_options": 1,
      "source_package_name": "Windows 11 v24H2 Security Baseline.zip",
      "source_package_sha256": "b75439a231c64edaccaad16a16268d199f56ce78273104e117d893f82cf174a5",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2011%20v24H2%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "e3e4b28b2cd10a222ebfbd7e998ea97e57fe68494b94c6953f274bd8432878f6.ipmsgpo",
      "artifact_sha256": "e3e4b28b2cd10a222ebfbd7e998ea97e57fe68494b94c6953f274bd8432878f6",
      "artifact_size": 90397,
      "backup_id": "{DD32F334-CB07-4579-96E3-06F27B6B5FAB}",
      "baseline_id": "microsoft-windows-11-24h2",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 3616,
          "path": "Backup.xml",
          "sha256": "078b15a72300a704d825f6d334e1cb4675dfb0ccba771a339bb388c10b018434"
        },
        {
          "bytes": 554,
          "path": "DomainSysvol/GPO/Machine/comment.cmtx",
          "sha256": "f4cb5d64e7a8cec20da34b276020efb31262ab81bc325d754578d60f87d5e387"
        },
        {
          "bytes": 8694,
          "path": "DomainSysvol/GPO/Machine/registry.pol",
          "sha256": "b4a4f5d9004fee88b3368fe971eeb225e0e19c784ff784375fe4fb65071f2412"
        },
        {
          "bytes": 605,
          "path": "bkupInfo.xml",
          "sha256": "8f289b7a58d8c88621cb35e44525ea9359b7ad0ac238c07bfc800629236976c2"
        },
        {
          "bytes": 76896,
          "path": "gpreport.xml",
          "sha256": "069ba0319b5b77b57a3dd2f7ef0da0a5431ec1d1347b90c6217521b6552ca2a1"
        }
      ],
      "name": "MSFT Windows 11 24H2 - Defender Antivirus",
      "purpose": "MSFTWindows1124H2DefenderAntivirus",
      "scope": "machine",
      "source_backup_path": "Windows 11 v24H2 Security Baseline/GPOs/{DD32F334-CB07-4579-96E3-06F27B6B5FAB}",
      "source_display_name": "MSFT Windows 11 24H2 - Defender Antivirus",
      "source_gpo_id": "{048EDF92-475E-4360-A38B-025342E2D833}",
      "source_options": 1,
      "source_package_name": "Windows 11 v24H2 Security Baseline.zip",
      "source_package_sha256": "b75439a231c64edaccaad16a16268d199f56ce78273104e117d893f82cf174a5",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2011%20v24H2%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "4f978786a934e758f2a1f25b305382694786656fe75979f23a0fb02714c5916e.ipmsgpo",
      "artifact_sha256": "4f978786a934e758f2a1f25b305382694786656fe75979f23a0fb02714c5916e",
      "artifact_size": 378194,
      "backup_id": "{02DB0E53-0925-4E5A-B775-E7A1A9370AB8}",
      "baseline_id": "microsoft-windows-11-25h2",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Applications",
        "DomainSysvol/GPO/Machine/Scripts",
        "DomainSysvol/GPO/Machine/Scripts/Shutdown",
        "DomainSysvol/GPO/Machine/Scripts/Startup",
        "DomainSysvol/GPO/Machine/microsoft",
        "DomainSysvol/GPO/Machine/microsoft/windows nt",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 8157,
          "path": "Backup.xml",
          "sha256": "162c029df407f0db44315607dd5bd74f808c1a7d67da9f067020e44911172ad4"
        },
        {
          "bytes": 696,
          "path": "DomainSysvol/GPO/Machine/comment.cmtx",
          "sha256": "e7ad740e0be87a27ce7c1385d3183b9ae40fc459ca4945846edf8d077a20285b"
        },
        {
          "bytes": 2196,
          "path": "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit/audit.csv",
          "sha256": "87be5144cf18bee60549cd169ee63542c65a7a92daf8358e56010302654add75"
        },
        {
          "bytes": 7936,
          "path": "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit/GptTmpl.inf",
          "sha256": "8c5509e4876e51c448e88add14088a6d7a96df9e1ba4786e6a90749f30ba8b98"
        },
        {
          "bytes": 24768,
          "path": "DomainSysvol/GPO/Machine/registry.pol",
          "sha256": "1cd0a0a9568efa2c910885c6ff573b24a9e0867b2d199dcf6fd537f1888a1398"
        },
        {
          "bytes": 595,
          "path": "bkupInfo.xml",
          "sha256": "8759b32db16197aff850269a6ea7629af0120ae80bd22306c6b8f1286054d517"
        },
        {
          "bytes": 333806,
          "path": "gpreport.xml",
          "sha256": "2a694b95b4d5b0353dbaa8ea5f430bacb3e2ca6fa0855cc72d9c86e5a548e3d7"
        }
      ],
      "name": "MSFT Windows 11 25H2 - Computer",
      "purpose": "MSFTWindows1125H2Computer",
      "scope": "machine",
      "source_backup_path": "Windows 11 v25H2 Security Baseline/GPOs/{02DB0E53-0925-4E5A-B775-E7A1A9370AB8}",
      "source_display_name": "MSFT Windows 11 25H2 - Computer",
      "source_gpo_id": "{1B6AAB4D-20DC-4956-9439-DD15694E2B6A}",
      "source_options": 1,
      "source_package_name": "Windows 11 v25H2 Security Baseline.zip",
      "source_package_sha256": "3517a53030a3e437c9fe00c04274d80965d3527a8eb0514520cba75023c376f7",
      "source_package_url": "https://download.microsoft.com/download/e99be2d2-e077-4986-a06b-6078051999dd/Windows%2011%20v25H2%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "d46ff77a02c18040c75477037838b5e02e1249a3cb33ba9338bb5883ded80320.ipmsgpo",
      "artifact_sha256": "d46ff77a02c18040c75477037838b5e02e1249a3cb33ba9338bb5883ded80320",
      "artifact_size": 355463,
      "backup_id": "{1879C2DC-00C6-4692-B167-15B9366DF5D4}",
      "baseline_id": "microsoft-windows-11-25h2",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Applications",
        "DomainSysvol/GPO/Machine/Scripts",
        "DomainSysvol/GPO/Machine/Scripts/Shutdown",
        "DomainSysvol/GPO/Machine/Scripts/Startup",
        "DomainSysvol/GPO/Machine/microsoft",
        "DomainSysvol/GPO/Machine/microsoft/windows nt",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 6150,
          "path": "Backup.xml",
          "sha256": "ec10e55fbf7018a6bc74f4903312e13870d52ba725d68a61e9ee863e6acae57c"
        },
        {
          "bytes": 555,
          "path": "DomainSysvol/GPO/Machine/comment.cmtx",
          "sha256": "e6d7b0805b21144958f6b70b5273bd3eab96950b59fbcb1654654f4924cbd35c"
        },
        {
          "bytes": 142,
          "path": "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit/GptTmpl.inf",
          "sha256": "07cba636ed9c1c30c4a4c228e555151f1fc43f7bfc941cbb221ed67297ea3dbc"
        },
        {
          "bytes": 26168,
          "path": "DomainSysvol/GPO/Machine/registry.pol",
          "sha256": "b13fd26fe01a1dbff1079308180c35b6daf8254f3b9826837629fa80f9c9fe4a"
        },
        {
          "bytes": 600,
          "path": "bkupInfo.xml",
          "sha256": "98b55ac6c581b1e528d50eb06542bf4b4ac81b90595eebf4758301e35a018fe1"
        },
        {
          "bytes": 321812,
          "path": "gpreport.xml",
          "sha256": "1e69446fc16731d464cc50518a813db50b4e066c5a90be59ecf1c9a82c3c3780"
        }
      ],
      "name": "MSFT Internet Explorer 11 - Computer",
      "purpose": "MSFTInternetExplorer11Computer",
      "scope": "machine",
      "source_backup_path": "Windows 11 v25H2 Security Baseline/GPOs/{1879C2DC-00C6-4692-B167-15B9366DF5D4}",
      "source_display_name": "MSFT Internet Explorer 11 - Computer",
      "source_gpo_id": "{D5398278-ABE5-4648-921E-D68A15AF59E9}",
      "source_options": 1,
      "source_package_name": "Windows 11 v25H2 Security Baseline.zip",
      "source_package_sha256": "3517a53030a3e437c9fe00c04274d80965d3527a8eb0514520cba75023c376f7",
      "source_package_url": "https://download.microsoft.com/download/e99be2d2-e077-4986-a06b-6078051999dd/Windows%2011%20v25H2%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "989f559db1a97650dcb04b6a3e53cb38c8e2429724e3fe4314693a114ebb04c8.ipmsgpo",
      "artifact_sha256": "989f559db1a97650dcb04b6a3e53cb38c8e2429724e3fe4314693a114ebb04c8",
      "artifact_size": 25128,
      "backup_id": "{56977988-BEEC-4E61-B649-731EC7AB997B}",
      "baseline_id": "microsoft-windows-11-25h2",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Applications",
        "DomainSysvol/GPO/Machine/microsoft",
        "DomainSysvol/GPO/Machine/microsoft/windows nt",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 5069,
          "path": "Backup.xml",
          "sha256": "7ed7aaeb86a374475dd3fa72bf8ddb8801bcb01419fd2550b4189d2ff249c852"
        },
        {
          "bytes": 901,
          "path": "DomainSysvol/GPO/User/comment.cmtx",
          "sha256": "4626e59f12f72f994ce0a1591e5fbcfb1c83cc60462c35d3dff42f745cb0ea30"
        },
        {
          "bytes": 534,
          "path": "DomainSysvol/GPO/User/registry.pol",
          "sha256": "bdc7178487ef6346e2e4796ac6aae54a2076f950cb541bb4bd88c7c4a6874a96"
        },
        {
          "bytes": 596,
          "path": "bkupInfo.xml",
          "sha256": "f4321c98d58adaf97c462017edf5a3a887275eab91fabe9b9d239c4e0ac50466"
        },
        {
          "bytes": 17996,
          "path": "gpreport.xml",
          "sha256": "529b3127c9a619475160ccb1d855d4eab52238b648a3a2eee8334a8a2bfd9af5"
        }
      ],
      "name": "MSFT Internet Explorer 11 - User",
      "purpose": "MSFTInternetExplorer11User",
      "scope": "user",
      "source_backup_path": "Windows 11 v25H2 Security Baseline/GPOs/{56977988-BEEC-4E61-B649-731EC7AB997B}",
      "source_display_name": "MSFT Internet Explorer 11 - User",
      "source_gpo_id": "{582D31BD-8974-43C8-B88B-FC18B4254E87}",
      "source_options": 2,
      "source_package_name": "Windows 11 v25H2 Security Baseline.zip",
      "source_package_sha256": "3517a53030a3e437c9fe00c04274d80965d3527a8eb0514520cba75023c376f7",
      "source_package_url": "https://download.microsoft.com/download/e99be2d2-e077-4986-a06b-6078051999dd/Windows%2011%20v25H2%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "c89b8521ffd0a7a3bd4dc83371bb26bbd28bd79444eb9d2d06f584af258f2775.ipmsgpo",
      "artifact_sha256": "c89b8521ffd0a7a3bd4dc83371bb26bbd28bd79444eb9d2d06f584af258f2775",
      "artifact_size": 25077,
      "backup_id": "{666ED8AB-DF4A-45CE-9666-61F802515051}",
      "baseline_id": "microsoft-windows-11-25h2",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Applications",
        "DomainSysvol/GPO/Machine/Scripts",
        "DomainSysvol/GPO/Machine/Scripts/Shutdown",
        "DomainSysvol/GPO/Machine/Scripts/Startup",
        "DomainSysvol/GPO/Machine/microsoft",
        "DomainSysvol/GPO/Machine/microsoft/windows nt",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 5761,
          "path": "Backup.xml",
          "sha256": "21da5e9cb86fa20b1876110423e6125ddeb13e35434bbe8793b352a1e2a0befd"
        },
        {
          "bytes": 614,
          "path": "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit/GptTmpl.inf",
          "sha256": "68bff0f76db5c82f3a3db00611190bd792c47d758750b507232bd6d8b17820df"
        },
        {
          "bytes": 602,
          "path": "bkupInfo.xml",
          "sha256": "54331e42a46a5126e05c650002a13e8e588a3c3f3770566bbc41d8ff19e4d0bf"
        },
        {
          "bytes": 18072,
          "path": "gpreport.xml",
          "sha256": "5f5feb5d01dd7a756d571177dde6bc2e46487f0e34754c4e025495145af37d65"
        }
      ],
      "name": "MSFT Windows 11 25H2 - Domain Security",
      "purpose": "MSFTWindows1125H2DomainSecurity",
      "scope": "domain",
      "source_backup_path": "Windows 11 v25H2 Security Baseline/GPOs/{666ED8AB-DF4A-45CE-9666-61F802515051}",
      "source_display_name": "MSFT Windows 11 25H2 - Domain Security",
      "source_gpo_id": "{E9F1D4BF-D7C0-4358-B1CD-6B1F7E1754D3}",
      "source_options": 1,
      "source_package_name": "Windows 11 v25H2 Security Baseline.zip",
      "source_package_sha256": "3517a53030a3e437c9fe00c04274d80965d3527a8eb0514520cba75023c376f7",
      "source_package_url": "https://download.microsoft.com/download/e99be2d2-e077-4986-a06b-6078051999dd/Windows%2011%20v25H2%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "1b2215aa9b9de6d852df698feb188060d1cb68030c2ac593b7894c98d50b6ce7.ipmsgpo",
      "artifact_sha256": "1b2215aa9b9de6d852df698feb188060d1cb68030c2ac593b7894c98d50b6ce7",
      "artifact_size": 25047,
      "backup_id": "{D233D0A9-D74E-4AEE-9B89-2398C7AD1DDE}",
      "baseline_id": "microsoft-windows-11-25h2",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Applications",
        "DomainSysvol/GPO/Machine/microsoft",
        "DomainSysvol/GPO/Machine/microsoft/windows nt",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 5065,
          "path": "Backup.xml",
          "sha256": "b5e83606c7dc42bc31cfbbed74afaa86ccf88d2cb9790c97abaf0fd90b155836"
        },
        {
          "bytes": 553,
          "path": "DomainSysvol/GPO/User/comment.cmtx",
          "sha256": "12586d4ccf801507d2dac5c72d688d1bca3c76f97af5d45422feefdcc2437796"
        },
        {
          "bytes": 436,
          "path": "DomainSysvol/GPO/User/registry.pol",
          "sha256": "4d7e373625f1d959c384377f67858dc590a81bc32b360c4878c8d03afc1524d0"
        },
        {
          "bytes": 591,
          "path": "bkupInfo.xml",
          "sha256": "aa567f319924d296900c6a362dcb4712899d276995ff5b310200b0213d457041"
        },
        {
          "bytes": 18370,
          "path": "gpreport.xml",
          "sha256": "dd30785f31106afe4326e60c758b48d5e87d21d1b4a03f14562d88be6339fc31"
        }
      ],
      "name": "MSFT Windows 11 25H2 - User",
      "purpose": "MSFTWindows1125H2User",
      "scope": "user",
      "source_backup_path": "Windows 11 v25H2 Security Baseline/GPOs/{D233D0A9-D74E-4AEE-9B89-2398C7AD1DDE}",
      "source_display_name": "MSFT Windows 11 25H2 - User",
      "source_gpo_id": "{83A5E982-986A-4447-A8A1-7945B71C18B3}",
      "source_options": 2,
      "source_package_name": "Windows 11 v25H2 Security Baseline.zip",
      "source_package_sha256": "3517a53030a3e437c9fe00c04274d80965d3527a8eb0514520cba75023c376f7",
      "source_package_url": "https://download.microsoft.com/download/e99be2d2-e077-4986-a06b-6078051999dd/Windows%2011%20v25H2%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "29e32e1a7ee74d44652eb1220362bf8f37c8243d648518a39cbeb513dd5828e5.ipmsgpo",
      "artifact_sha256": "29e32e1a7ee74d44652eb1220362bf8f37c8243d648518a39cbeb513dd5828e5",
      "artifact_size": 87828,
      "backup_id": "{D42CD0A5-F321-4CB1-ADA9-03A0F0A6E3B2}",
      "baseline_id": "microsoft-windows-11-25h2",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 3616,
          "path": "Backup.xml",
          "sha256": "3d3531f586dbd39aa84882c3b9f9d2c092b159fc74d84601d38dc8c8ef064997"
        },
        {
          "bytes": 629,
          "path": "DomainSysvol/GPO/Machine/comment.cmtx",
          "sha256": "d8bc5709590e0e13f441ab16322a50c297552fd2fa79661e5608433e6822fcda"
        },
        {
          "bytes": 8618,
          "path": "DomainSysvol/GPO/Machine/registry.pol",
          "sha256": "dd6dde6921f61bf5840ff7cfe549fba825ddb3fce41f8bd7991493df1bfd134c"
        },
        {
          "bytes": 605,
          "path": "bkupInfo.xml",
          "sha256": "cd4ff5a255548e019613d887d7749d039ff3f52222252bbc20d541eccc91d4ec"
        },
        {
          "bytes": 74328,
          "path": "gpreport.xml",
          "sha256": "770d3386592816cf889218a726a2d8279c75901df29ee0e6f6d760e9b5c6bde6"
        }
      ],
      "name": "MSFT Windows 11 25H2 - Defender Antivirus",
      "purpose": "MSFTWindows1125H2DefenderAntivirus",
      "scope": "machine",
      "source_backup_path": "Windows 11 v25H2 Security Baseline/GPOs/{D42CD0A5-F321-4CB1-ADA9-03A0F0A6E3B2}",
      "source_display_name": "MSFT Windows 11 25H2 - Defender Antivirus",
      "source_gpo_id": "{048EDF92-475E-4360-A38B-025342E2D833}",
      "source_options": 1,
      "source_package_name": "Windows 11 v25H2 Security Baseline.zip",
      "source_package_sha256": "3517a53030a3e437c9fe00c04274d80965d3527a8eb0514520cba75023c376f7",
      "source_package_url": "https://download.microsoft.com/download/e99be2d2-e077-4986-a06b-6078051999dd/Windows%2011%20v25H2%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "b284ad5a7d4d6cc39c6dda64016cb1422af0db0e336add61ab3a0368b817d3c3.ipmsgpo",
      "artifact_sha256": "b284ad5a7d4d6cc39c6dda64016cb1422af0db0e336add61ab3a0368b817d3c3",
      "artifact_size": 40723,
      "backup_id": "{E2D5B48E-8BB0-4ACC-AEB6-8DD82FDD825F}",
      "baseline_id": "microsoft-windows-11-25h2",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Scripts",
        "DomainSysvol/GPO/Machine/Scripts/Shutdown",
        "DomainSysvol/GPO/Machine/Scripts/Startup",
        "DomainSysvol/GPO/Machine/microsoft",
        "DomainSysvol/GPO/Machine/microsoft/windows nt",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 5792,
          "path": "Backup.xml",
          "sha256": "ba3fb0fc5e8c0904d7448249c5bbddfbb422b5e785f4373b2fbd951edb9c4a56"
        },
        {
          "bytes": 557,
          "path": "DomainSysvol/GPO/Machine/comment.cmtx",
          "sha256": "7e62a37b598c50ae15bb714c96be700b2764f52ef5b1e9ae6e60b8622a5d4613"
        },
        {
          "bytes": 142,
          "path": "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit/GptTmpl.inf",
          "sha256": "07cba636ed9c1c30c4a4c228e555151f1fc43f7bfc941cbb221ed67297ea3dbc"
        },
        {
          "bytes": 1862,
          "path": "DomainSysvol/GPO/Machine/registry.pol",
          "sha256": "67c1f37f8c22e56c476b39b30b3060d0b69afe7a88fc66bda3557260632d87c2"
        },
        {
          "bytes": 596,
          "path": "bkupInfo.xml",
          "sha256": "a258d90468b044b89416b176019bb9d76ab0c25cffd380139946a6904885b4b9"
        },
        {
          "bytes": 31738,
          "path": "gpreport.xml",
          "sha256": "ebd737f957b2a11842eeb72efa2a1d9f14be8ef416466ed76cae11524287efed"
        }
      ],
      "name": "MSFT Windows 11 25H2 - BitLocker",
      "purpose": "MSFTWindows1125H2BitLocker",
      "scope": "machine",
      "source_backup_path": "Windows 11 v25H2 Security Baseline/GPOs/{E2D5B48E-8BB0-4ACC-AEB6-8DD82FDD825F}",
      "source_display_name": "MSFT Windows 11 25H2 - BitLocker",
      "source_gpo_id": "{F9CA6C42-3A57-4D81-88BF-6CD8289FD1F5}",
      "source_options": 1,
      "source_package_name": "Windows 11 v25H2 Security Baseline.zip",
      "source_package_sha256": "3517a53030a3e437c9fe00c04274d80965d3527a8eb0514520cba75023c376f7",
      "source_package_url": "https://download.microsoft.com/download/e99be2d2-e077-4986-a06b-6078051999dd/Windows%2011%20v25H2%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "d85636c61486bdf7ebf41d7a05a80be3bd5d4aa3db6d1b122ee033a96ca38c69.ipmsgpo",
      "artifact_sha256": "d85636c61486bdf7ebf41d7a05a80be3bd5d4aa3db6d1b122ee033a96ca38c69",
      "artifact_size": 41665,
      "backup_id": "{FC357767-040F-49C3-965E-B071D17C29A0}",
      "baseline_id": "microsoft-windows-11-25h2",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Scripts",
        "DomainSysvol/GPO/Machine/Scripts/Shutdown",
        "DomainSysvol/GPO/Machine/Scripts/Startup",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 4453,
          "path": "Backup.xml",
          "sha256": "1a7300164f3d220cf23ed63bfd6a8725c4a688b5494c810d9659f28bf26a1d1c"
        },
        {
          "bytes": 549,
          "path": "DomainSysvol/GPO/Machine/comment.cmtx",
          "sha256": "94f49ee096c38f34ddf86a3d864661da5a39cca6a641ce5db6c159bf106d8e01"
        },
        {
          "bytes": 1392,
          "path": "DomainSysvol/GPO/Machine/registry.pol",
          "sha256": "abb45d64d366833f5fb6901a54586c9f49123a4e4284d0906bd03d5a688354ec"
        },
        {
          "bytes": 603,
          "path": "bkupInfo.xml",
          "sha256": "19462864610eb345fa79b02740311790df63b3cef8314b915800e1a91a6e4476"
        },
        {
          "bytes": 34636,
          "path": "gpreport.xml",
          "sha256": "35652e1478c496b8319a6c366e9645055ba4316f12c0bace25b9effb976da67c"
        }
      ],
      "name": "MSFT Windows 11 25H2 - Credential Guard",
      "purpose": "MSFTWindows1125H2CredentialGuard",
      "scope": "machine",
      "source_backup_path": "Windows 11 v25H2 Security Baseline/GPOs/{FC357767-040F-49C3-965E-B071D17C29A0}",
      "source_display_name": "MSFT Windows 11 25H2 - Credential Guard",
      "source_gpo_id": "{3459AD93-6648-423E-9777-0C82975217D5}",
      "source_options": 1,
      "source_package_name": "Windows 11 v25H2 Security Baseline.zip",
      "source_package_sha256": "3517a53030a3e437c9fe00c04274d80965d3527a8eb0514520cba75023c376f7",
      "source_package_url": "https://download.microsoft.com/download/e99be2d2-e077-4986-a06b-6078051999dd/Windows%2011%20v25H2%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "f88bc858479bd991a40afe8a8df895df9789d4866c114e5abdd7746c7bfd8e83.ipmsgpo",
      "artifact_sha256": "f88bc858479bd991a40afe8a8df895df9789d4866c114e5abdd7746c7bfd8e83",
      "artifact_size": 353712,
      "backup_id": "{07177AF8-97DF-407D-89A6-C875CD1784BC}",
      "baseline_id": "microsoft-windows-server-2016",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Applications",
        "DomainSysvol/GPO/Machine/microsoft",
        "DomainSysvol/GPO/Machine/microsoft/windows nt",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 5050,
          "path": "Backup.xml",
          "sha256": "98fe1a09dd75c3d85dabfc5a9707822b723a4802139ab8c033586de53f7962bd"
        },
        {
          "bytes": 555,
          "path": "DomainSysvol/GPO/Machine/comment.cmtx",
          "sha256": "e6d7b0805b21144958f6b70b5273bd3eab96950b59fbcb1654654f4924cbd35c"
        },
        {
          "bytes": 26148,
          "path": "DomainSysvol/GPO/Machine/registry.pol",
          "sha256": "016b7dbeebc8b72ed99af71cfd07f04f33fc225d8e26c3f17051dd09ac67a542"
        },
        {
          "bytes": 599,
          "path": "bkupInfo.xml",
          "sha256": "0a093d9ca5f316309ddc79241390aa2b16f88abeeb16458924d491956281f401"
        },
        {
          "bytes": 321328,
          "path": "gpreport.xml",
          "sha256": "3fc0a62d6bedbaa0d799b666a922a059bf81d65096cd4c6b4dbe5c4cec46d16e"
        }
      ],
      "name": "SCM Internet Explorer 11 - Computer",
      "purpose": "SCMInternetExplorer11Computer",
      "scope": "machine",
      "source_backup_path": "Windows-10-RS1-and-Server-2016-Security-Baseline/GPOs/{07177AF8-97DF-407D-89A6-C875CD1784BC}",
      "source_display_name": "SCM Internet Explorer 11 - Computer",
      "source_gpo_id": "{FFDE8540-331A-4BBE-957F-96D729703359}",
      "source_options": 1,
      "source_package_name": "Windows 10 Version 1607 and Windows Server 2016 Security Baseline.zip",
      "source_package_sha256": "47a877aa5180161e31a9b7dbeb7b6fba6b841e71bcd88cf2857e03d0e7e710d0",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2010%20Version%201607%20and%20Windows%20Server%202016%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "5e4f738898f5921ec18ec228118bb06363d48487e7dc36846e422c21aecdd669.ipmsgpo",
      "artifact_sha256": "5e4f738898f5921ec18ec228118bb06363d48487e7dc36846e422c21aecdd669",
      "artifact_size": 228362,
      "backup_id": "{088E04EC-440C-48CB-A8D7-A89D0162FBFB}",
      "baseline_id": "microsoft-windows-server-2016",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Applications",
        "DomainSysvol/GPO/Machine/Preferences",
        "DomainSysvol/GPO/Machine/Preferences/Registry",
        "DomainSysvol/GPO/Machine/Scripts",
        "DomainSysvol/GPO/Machine/Scripts/Shutdown",
        "DomainSysvol/GPO/Machine/Scripts/Startup",
        "DomainSysvol/GPO/Machine/microsoft",
        "DomainSysvol/GPO/Machine/microsoft/windows nt",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 9503,
          "path": "Backup.xml",
          "sha256": "027bad29eb6a22a86d59b0507bde71d7091498dbd40134588e440512644dff01"
        },
        {
          "bytes": 549,
          "path": "DomainSysvol/GPO/Machine/comment.cmtx",
          "sha256": "9d65171cda6f7ba25402c55ab480b9f2abd1497e5e5e88cf1cd8c04f3f8bb08d"
        },
        {
          "bytes": 2039,
          "path": "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit/audit.csv",
          "sha256": "72e23b923f635faced7aceab8a24f7c31cd43833f4cb6a7c6426030cca5774ed"
        },
        {
          "bytes": 9172,
          "path": "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit/GptTmpl.inf",
          "sha256": "38d4693bb8360377228d5f90b4491df5635172aa50a427862ee09a9594ca3ffe"
        },
        {
          "bytes": 9910,
          "path": "DomainSysvol/GPO/Machine/registry.pol",
          "sha256": "bf7f9730335d35ca27ab0056e9df1ff5d05849b7d601f78875d1cd22f39fe409"
        },
        {
          "bytes": 720,
          "path": "DomainSysvol/GPO/User/comment.cmtx",
          "sha256": "0a8282f81b3160402cfbcbfc19ab6664a543df703be83960bb285d18b5263a4f"
        },
        {
          "bytes": 8,
          "path": "DomainSysvol/GPO/User/registry.pol",
          "sha256": "5bb1f21f806938a043563024b13b33d74a2b95b767c5f81bde8456e9d0413a89"
        },
        {
          "bytes": 623,
          "path": "bkupInfo.xml",
          "sha256": "6ad3dad481e30d73808e8507cb060aa34ba9247a6c96ac9ad78ff81a2bfde124"
        },
        {
          "bytes": 195790,
          "path": "gpreport.xml",
          "sha256": "e8efb8a401a367675025408bf841e24300293b2196ebf87ea80efc3d92ebebde"
        }
      ],
      "name": "SCM Windows Server 2016 - Member Server Baseline - Computer",
      "purpose": "SCMWindowsServer2016MemberServerBaselineComputer",
      "scope": "machine",
      "source_backup_path": "Windows-10-RS1-and-Server-2016-Security-Baseline/GPOs/{088E04EC-440C-48CB-A8D7-A89D0162FBFB}",
      "source_display_name": "SCM Windows Server 2016 - Member Server Baseline - Computer",
      "source_gpo_id": "{B9089292-4897-4AFC-8D31-E8A2FE36A29E}",
      "source_options": 1,
      "source_package_name": "Windows 10 Version 1607 and Windows Server 2016 Security Baseline.zip",
      "source_package_sha256": "47a877aa5180161e31a9b7dbeb7b6fba6b841e71bcd88cf2857e03d0e7e710d0",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2010%20Version%201607%20and%20Windows%20Server%202016%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "fbee5845109f9727d706deebd273ef9ae5cd10cfd93414376a39e6588cad021e.ipmsgpo",
      "artifact_sha256": "fbee5845109f9727d706deebd273ef9ae5cd10cfd93414376a39e6588cad021e",
      "artifact_size": 24194,
      "backup_id": "{1D2C9D38-6BB1-4C90-B5EB-2850EA18AE06}",
      "baseline_id": "microsoft-windows-server-2016",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Applications",
        "DomainSysvol/GPO/Machine/microsoft",
        "DomainSysvol/GPO/Machine/microsoft/windows nt",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 5008,
          "path": "Backup.xml",
          "sha256": "683ac69d94df73348fee358caf415269d6cf39bd44d32c41bd4fff66b4d4f292"
        },
        {
          "bytes": 612,
          "path": "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit/GptTmpl.inf",
          "sha256": "a2d01aed3eb819470a9e909a29a3a972dd371356d1ad6a8c9843486b2e6eeb47"
        },
        {
          "bytes": 612,
          "path": "bkupInfo.xml",
          "sha256": "f445393c1ea2f1441bfbfd3371598c9573e65bb3be1ab0d0036050783bee971c"
        },
        {
          "bytes": 17934,
          "path": "gpreport.xml",
          "sha256": "6f38aebe76922f1355a822093e06fb6a231ddf714b9b4b331e73535f71c11e0d"
        }
      ],
      "name": "SCM Windows 10 and Server 2016 - Domain Security",
      "purpose": "SCMWindows10andServer2016DomainSecurity",
      "scope": "domain",
      "source_backup_path": "Windows-10-RS1-and-Server-2016-Security-Baseline/GPOs/{1D2C9D38-6BB1-4C90-B5EB-2850EA18AE06}",
      "source_display_name": "SCM Windows 10 and Server 2016 - Domain Security",
      "source_gpo_id": "{81016E18-6CCB-4009-B43A-08BB7D120B05}",
      "source_options": 1,
      "source_package_name": "Windows 10 Version 1607 and Windows Server 2016 Security Baseline.zip",
      "source_package_sha256": "47a877aa5180161e31a9b7dbeb7b6fba6b841e71bcd88cf2857e03d0e7e710d0",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2010%20Version%201607%20and%20Windows%20Server%202016%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "c47aa2eaaee8bb914057f00ac0a33c8090a054d4b4b9b2357b49568ad324112a.ipmsgpo",
      "artifact_sha256": "c47aa2eaaee8bb914057f00ac0a33c8090a054d4b4b9b2357b49568ad324112a",
      "artifact_size": 236917,
      "backup_id": "{37BBB33A-A159-427D-AD58-67B1BE126AD6}",
      "baseline_id": "microsoft-windows-server-2016",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Applications",
        "DomainSysvol/GPO/Machine/Preferences",
        "DomainSysvol/GPO/Machine/Preferences/Registry",
        "DomainSysvol/GPO/Machine/Scripts",
        "DomainSysvol/GPO/Machine/Scripts/Shutdown",
        "DomainSysvol/GPO/Machine/Scripts/Startup",
        "DomainSysvol/GPO/Machine/microsoft",
        "DomainSysvol/GPO/Machine/microsoft/windows nt",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 9327,
          "path": "Backup.xml",
          "sha256": "5bea965dbe6b7028b20b63af6533c218417214e1e0ea9bbbf8467b69b5ced264"
        },
        {
          "bytes": 549,
          "path": "DomainSysvol/GPO/Machine/comment.cmtx",
          "sha256": "9d65171cda6f7ba25402c55ab480b9f2abd1497e5e5e88cf1cd8c04f3f8bb08d"
        },
        {
          "bytes": 2337,
          "path": "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit/audit.csv",
          "sha256": "67e752572c51f9d3bf68d930ccb1e594932a64b14be81a765b3e0ed22211d31e"
        },
        {
          "bytes": 9468,
          "path": "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit/GptTmpl.inf",
          "sha256": "516ad390ce258eba4251aa5acb7e5c11124869b67bb780fcd64e0e6de4791f10"
        },
        {
          "bytes": 16790,
          "path": "DomainSysvol/GPO/Machine/registry.pol",
          "sha256": "0a42319815f77cfe6373a161567e3d82063ba193fa565a7b39b460435c8bed8f"
        },
        {
          "bytes": 720,
          "path": "DomainSysvol/GPO/User/comment.cmtx",
          "sha256": "0a8282f81b3160402cfbcbfc19ab6664a543df703be83960bb285d18b5263a4f"
        },
        {
          "bytes": 8,
          "path": "DomainSysvol/GPO/User/registry.pol",
          "sha256": "5bb1f21f806938a043563024b13b33d74a2b95b767c5f81bde8456e9d0413a89"
        },
        {
          "bytes": 616,
          "path": "bkupInfo.xml",
          "sha256": "7e02937674ca09dc9d88e17327a8db09478d4d55c2abaa937d45563e78fcd89f"
        },
        {
          "bytes": 197054,
          "path": "gpreport.xml",
          "sha256": "4b1e73d6c55399cc1895dd5a24b202b03e280a92eed4c1d497ba65355902795f"
        }
      ],
      "name": "SCM Windows Server 2016 - Domain Controller Baseline",
      "purpose": "SCMWindowsServer2016DomainControllerBaseline",
      "scope": "machine",
      "source_backup_path": "Windows-10-RS1-and-Server-2016-Security-Baseline/GPOs/{37BBB33A-A159-427D-AD58-67B1BE126AD6}",
      "source_display_name": "SCM Windows Server 2016 - Domain Controller Baseline",
      "source_gpo_id": "{9D437703-F551-4E1E-9B4C-E6480DCA6154}",
      "source_options": 1,
      "source_package_name": "Windows 10 Version 1607 and Windows Server 2016 Security Baseline.zip",
      "source_package_sha256": "47a877aa5180161e31a9b7dbeb7b6fba6b841e71bcd88cf2857e03d0e7e710d0",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2010%20Version%201607%20and%20Windows%20Server%202016%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "53efec9e6be403fa49d54879e87773aac871cb1c1334924c282fe5dcd6ce2314.ipmsgpo",
      "artifact_sha256": "53efec9e6be403fa49d54879e87773aac871cb1c1334924c282fe5dcd6ce2314",
      "artifact_size": 34326,
      "backup_id": "{4095647A-14FE-4CE4-955A-F2311B0D62D1}",
      "baseline_id": "microsoft-windows-server-2016",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 3609,
          "path": "Backup.xml",
          "sha256": "20531f1056026c4b1e8a2760cd21ca1d74b51461609545c36f020c9432a53bc0"
        },
        {
          "bytes": 554,
          "path": "DomainSysvol/GPO/Machine/comment.cmtx",
          "sha256": "f4cb5d64e7a8cec20da34b276020efb31262ab81bc325d754578d60f87d5e387"
        },
        {
          "bytes": 1248,
          "path": "DomainSysvol/GPO/Machine/registry.pol",
          "sha256": "a033c00f11d957db73d52a09b02fd7929f47feb2d54d43563d7dc0e0993c92d9"
        },
        {
          "bytes": 605,
          "path": "bkupInfo.xml",
          "sha256": "6229ae252082861f9ef99b58073a89ccf8026548005d8b9ac088d4f64cbf7a75"
        },
        {
          "bytes": 28278,
          "path": "gpreport.xml",
          "sha256": "c2c25557ccc6a134ecae60402a19adf0173b1eece65974af4c0b3cb5e8baa7de"
        }
      ],
      "name": "SCM Windows 10 and Server 2016 - Defender",
      "purpose": "SCMWindows10andServer2016Defender",
      "scope": "machine",
      "source_backup_path": "Windows-10-RS1-and-Server-2016-Security-Baseline/GPOs/{4095647A-14FE-4CE4-955A-F2311B0D62D1}",
      "source_display_name": "SCM Windows 10 and Server 2016 - Defender",
      "source_gpo_id": "{E4347697-F22C-4600-9C28-089CC391D3DD}",
      "source_options": 1,
      "source_package_name": "Windows 10 Version 1607 and Windows Server 2016 Security Baseline.zip",
      "source_package_sha256": "47a877aa5180161e31a9b7dbeb7b6fba6b841e71bcd88cf2857e03d0e7e710d0",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2010%20Version%201607%20and%20Windows%20Server%202016%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "a96bbeca3bc4e7720c23a6040f3dd298dc32d73625b5a13eb0fcdb65a62b792a.ipmsgpo",
      "artifact_sha256": "a96bbeca3bc4e7720c23a6040f3dd298dc32d73625b5a13eb0fcdb65a62b792a",
      "artifact_size": 27179,
      "backup_id": "{714FD77E-8FDD-4CB0-B3F7-FF49815473FF}",
      "baseline_id": "microsoft-windows-server-2016",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 3699,
          "path": "Backup.xml",
          "sha256": "e9507c2dd342f692f6c23104b4ba8480164109b675a0f142da4b386faefb8846"
        },
        {
          "bytes": 549,
          "path": "DomainSysvol/GPO/Machine/comment.cmtx",
          "sha256": "94f49ee096c38f34ddf86a3d864661da5a39cca6a641ce5db6c159bf106d8e01"
        },
        {
          "bytes": 708,
          "path": "DomainSysvol/GPO/Machine/registry.pol",
          "sha256": "b7c7a44ccc1b6a09fe845b3fbf57462c8ac152c75f22dd1c40ebe9059a55ca58"
        },
        {
          "bytes": 613,
          "path": "bkupInfo.xml",
          "sha256": "7b2afd879a54f87fcc30e1e91c0cac3ebf75327d1566d7ed91da82e39842e3de"
        },
        {
          "bytes": 21578,
          "path": "gpreport.xml",
          "sha256": "55a8b2699cb16ac9467316b9e88c094857aa45a30b1ff37734a7ffcb46952eab"
        }
      ],
      "name": "SCM Windows 10 and Server 2016 - Credential Guard",
      "purpose": "SCMWindows10andServer2016CredentialGuard",
      "scope": "machine",
      "source_backup_path": "Windows-10-RS1-and-Server-2016-Security-Baseline/GPOs/{714FD77E-8FDD-4CB0-B3F7-FF49815473FF}",
      "source_display_name": "SCM Windows 10 and Server 2016 - Credential Guard",
      "source_gpo_id": "{BD4270E0-264A-4E74-812E-CB1F437A8088}",
      "source_options": 1,
      "source_package_name": "Windows 10 Version 1607 and Windows Server 2016 Security Baseline.zip",
      "source_package_sha256": "47a877aa5180161e31a9b7dbeb7b6fba6b841e71bcd88cf2857e03d0e7e710d0",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2010%20Version%201607%20and%20Windows%20Server%202016%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "825dd6a0097ba64f2b7340699534c3f09cffcac5ee004aa6c11a46efee93487a.ipmsgpo",
      "artifact_sha256": "825dd6a0097ba64f2b7340699534c3f09cffcac5ee004aa6c11a46efee93487a",
      "artifact_size": 24167,
      "backup_id": "{9C87270F-7704-41D9-A76D-C8B9ADB1794A}",
      "baseline_id": "microsoft-windows-server-2016",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 3608,
          "path": "Backup.xml",
          "sha256": "f6c073620833c979b2eb8a9fc7bf4a6bed8a4bf1b21fc546ab2043784d66790b"
        },
        {
          "bytes": 556,
          "path": "DomainSysvol/GPO/User/comment.cmtx",
          "sha256": "7123a668aff41be95cc2b96c559079505352c2c0929e83527fccc47ba40509a7"
        },
        {
          "bytes": 362,
          "path": "DomainSysvol/GPO/User/registry.pol",
          "sha256": "5f252c8f0a34d15bacf825ee7737d07c34e2f5af54c47d4dfa94647974a2acdb"
        },
        {
          "bytes": 619,
          "path": "bkupInfo.xml",
          "sha256": "c8e45da6d822a8ad8acea0c0d73393c920aa0e29f33b09921cf0d646664250de"
        },
        {
          "bytes": 18990,
          "path": "gpreport.xml",
          "sha256": "1d2567769b4d3b229f43810ce1843531addf657066f5e5591ae07e1a7f00b340"
        }
      ],
      "name": "SCM Windows Server 2016 - Member Server Baseline - User",
      "purpose": "SCMWindowsServer2016MemberServerBaselineUser",
      "scope": "user",
      "source_backup_path": "Windows-10-RS1-and-Server-2016-Security-Baseline/GPOs/{9C87270F-7704-41D9-A76D-C8B9ADB1794A}",
      "source_display_name": "SCM Windows Server 2016 - Member Server Baseline - User",
      "source_gpo_id": "{AA25E0E9-40BC-4D4C-8FE7-D3B82358B8E0}",
      "source_options": 2,
      "source_package_name": "Windows 10 Version 1607 and Windows Server 2016 Security Baseline.zip",
      "source_package_sha256": "47a877aa5180161e31a9b7dbeb7b6fba6b841e71bcd88cf2857e03d0e7e710d0",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2010%20Version%201607%20and%20Windows%20Server%202016%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "4434643dd60d7b6f2c81310bf293b87ddd0fcf255e03e98af8ef366eb3c79213.ipmsgpo",
      "artifact_sha256": "4434643dd60d7b6f2c81310bf293b87ddd0fcf255e03e98af8ef366eb3c79213",
      "artifact_size": 24258,
      "backup_id": "{B0AA555D-B555-4832-9BA6-2D5A973A7B92}",
      "baseline_id": "microsoft-windows-server-2016",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Applications",
        "DomainSysvol/GPO/Machine/microsoft",
        "DomainSysvol/GPO/Machine/microsoft/windows nt",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 5068,
          "path": "Backup.xml",
          "sha256": "a862520042f8acc0026504195528bd193d37064caa116e907c66fce0da38e238"
        },
        {
          "bytes": 901,
          "path": "DomainSysvol/GPO/User/comment.cmtx",
          "sha256": "4626e59f12f72f994ce0a1591e5fbcfb1c83cc60462c35d3dff42f745cb0ea30"
        },
        {
          "bytes": 534,
          "path": "DomainSysvol/GPO/User/registry.pol",
          "sha256": "bdc7178487ef6346e2e4796ac6aae54a2076f950cb541bb4bd88c7c4a6874a96"
        },
        {
          "bytes": 595,
          "path": "bkupInfo.xml",
          "sha256": "95fe661212c3a016fdad9a069b8bd9f7db9236a91e7d13bd1ebe5e791b92233d"
        },
        {
          "bytes": 17128,
          "path": "gpreport.xml",
          "sha256": "29907dc28c6a589b9c6fcf81ec82a0d15b07790ce6d1d19d136fa0d85b39471a"
        }
      ],
      "name": "SCM Internet Explorer 11 - User",
      "purpose": "SCMInternetExplorer11User",
      "scope": "user",
      "source_backup_path": "Windows-10-RS1-and-Server-2016-Security-Baseline/GPOs/{B0AA555D-B555-4832-9BA6-2D5A973A7B92}",
      "source_display_name": "SCM Internet Explorer 11 - User",
      "source_gpo_id": "{DC92BC89-A6CF-4210-9E43-B1B708B21277}",
      "source_options": 2,
      "source_package_name": "Windows 10 Version 1607 and Windows Server 2016 Security Baseline.zip",
      "source_package_sha256": "47a877aa5180161e31a9b7dbeb7b6fba6b841e71bcd88cf2857e03d0e7e710d0",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2010%20Version%201607%20and%20Windows%20Server%202016%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "110c59713fd86f73bd1b55c78355e5181910f8f9b0da316ce4edd5dda7d1f3bd.ipmsgpo",
      "artifact_sha256": "110c59713fd86f73bd1b55c78355e5181910f8f9b0da316ce4edd5dda7d1f3bd",
      "artifact_size": 31252,
      "backup_id": "{7D41EEC9-3F30-4473-9447-E77D6EEF0E17}",
      "baseline_id": "microsoft-windows-server-2019",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 3720,
          "path": "Backup.xml",
          "sha256": "9523d5badea8aa3bf88706429828a7ddc9446fd6c467eb25fd58260a8b92e964"
        },
        {
          "bytes": 549,
          "path": "DomainSysvol/GPO/Machine/comment.cmtx",
          "sha256": "94f49ee096c38f34ddf86a3d864661da5a39cca6a641ce5db6c159bf106d8e01"
        },
        {
          "bytes": 1034,
          "path": "DomainSysvol/GPO/Machine/registry.pol",
          "sha256": "e82fdbd8ed33e529c99d7e6f5e5bfa35ecc22b0656ade2bb88f02fa162d952cb"
        },
        {
          "bytes": 633,
          "path": "bkupInfo.xml",
          "sha256": "aa4c5ba3c9b23eb79b8fb223122addde64f8bbabccc298c82a85ff72bdb0b837"
        },
        {
          "bytes": 25284,
          "path": "gpreport.xml",
          "sha256": "f4a30a320a834ca9effc946c3baa2c55e609de49d84a7804c2a08a48e8f1cb21"
        }
      ],
      "name": "MSFT Windows 10 1809 and Server 2019 Member Server - Credential Guard",
      "purpose": "MSFTWindows101809andServer2019MemberServerCredentialGuard",
      "scope": "machine",
      "source_backup_path": "GPOs/{7D41EEC9-3F30-4473-9447-E77D6EEF0E17}",
      "source_display_name": "MSFT Windows 10 1809 and Server 2019 Member Server - Credential Guard",
      "source_gpo_id": "{56B8B726-E3D2-4D7B-8451-A8F4068148B2}",
      "source_options": 1,
      "source_package_name": "Windows 10 Version 1809 and Windows Server 2019 Security Baseline.zip",
      "source_package_sha256": "575ddaf39ef364ea6da678e22b0a988ea316eb240f73fbf618092a02647245bc",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2010%20Version%201809%20and%20Windows%20Server%202019%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "c4d47e4be1b04b792203bbb382a431e39d264dc346e7f3d3d28362d3ceabb0d3.ipmsgpo",
      "artifact_sha256": "c4d47e4be1b04b792203bbb382a431e39d264dc346e7f3d3d28362d3ceabb0d3",
      "artifact_size": 31239,
      "backup_id": "{7EA149BF-56B3-42CF-AF68-3FC789510ADD}",
      "baseline_id": "microsoft-windows-server-2019",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 3724,
          "path": "Backup.xml",
          "sha256": "aae2450f6ff2509e9c66bbfe8ef402aeafcc691d0bb727f6874c5c375ab7f620"
        },
        {
          "bytes": 549,
          "path": "DomainSysvol/GPO/Machine/comment.cmtx",
          "sha256": "94f49ee096c38f34ddf86a3d864661da5a39cca6a641ce5db6c159bf106d8e01"
        },
        {
          "bytes": 1034,
          "path": "DomainSysvol/GPO/Machine/registry.pol",
          "sha256": "41e474f8805e0230b6a8d9a4c2005ef8c3b614e74847fd25f2b8ecd7e48b356e"
        },
        {
          "bytes": 638,
          "path": "bkupInfo.xml",
          "sha256": "75c913f198dff1c15f974a32625cabbabb2bcf3c3a779d964ee8ff726ab04ab5"
        },
        {
          "bytes": 25262,
          "path": "gpreport.xml",
          "sha256": "614bf4b9f52f1e232814e97728bbd5cedbab44b8d1a59ed7de0e15d623f86ee4"
        }
      ],
      "name": "MSFT Windows Server 2019 - Domain Controller Virtualization Based Security",
      "purpose": "MSFTWindowsServer2019DomainControllerVirtualizationBasedSecurity",
      "scope": "machine",
      "source_backup_path": "GPOs/{7EA149BF-56B3-42CF-AF68-3FC789510ADD}",
      "source_display_name": "MSFT Windows Server 2019 - Domain Controller Virtualization Based Security",
      "source_gpo_id": "{E912B82F-B367-4C58-9E13-07AC0491F12F}",
      "source_options": 1,
      "source_package_name": "Windows 10 Version 1809 and Windows Server 2019 Security Baseline.zip",
      "source_package_sha256": "575ddaf39ef364ea6da678e22b0a988ea316eb240f73fbf618092a02647245bc",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2010%20Version%201809%20and%20Windows%20Server%202019%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "773aab5da49365089975547254219c32f73adbd2c151efe0111e93e32ffc8ac3.ipmsgpo",
      "artifact_sha256": "773aab5da49365089975547254219c32f73adbd2c151efe0111e93e32ffc8ac3",
      "artifact_size": 353149,
      "backup_id": "{ABFB52F2-1560-4100-9103-8C10F57DC9DE}",
      "baseline_id": "microsoft-windows-server-2019",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Applications",
        "DomainSysvol/GPO/Machine/Scripts",
        "DomainSysvol/GPO/Machine/Scripts/Shutdown",
        "DomainSysvol/GPO/Machine/Scripts/Startup",
        "DomainSysvol/GPO/Machine/microsoft",
        "DomainSysvol/GPO/Machine/microsoft/windows nt",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 6148,
          "path": "Backup.xml",
          "sha256": "80badbed8b3ed7fed41e176a68638637921ad116e62dd4bc211c9f92259bdc08"
        },
        {
          "bytes": 555,
          "path": "DomainSysvol/GPO/Machine/comment.cmtx",
          "sha256": "e6d7b0805b21144958f6b70b5273bd3eab96950b59fbcb1654654f4924cbd35c"
        },
        {
          "bytes": 142,
          "path": "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit/GptTmpl.inf",
          "sha256": "07cba636ed9c1c30c4a4c228e555151f1fc43f7bfc941cbb221ed67297ea3dbc"
        },
        {
          "bytes": 25970,
          "path": "DomainSysvol/GPO/Machine/registry.pol",
          "sha256": "8a5b1628731d7516b4d45144cef6c9aab6e823b62bcd4db226e83c5820e088cc"
        },
        {
          "bytes": 600,
          "path": "bkupInfo.xml",
          "sha256": "a9d9a1022c312f8b1833269906a689b7fb80fc3c763db4ba64643783e8d91400"
        },
        {
          "bytes": 319698,
          "path": "gpreport.xml",
          "sha256": "4cb5cce249b52ba49d767fad0f7d38e2af9d36a010b679de3cb028377b637e36"
        }
      ],
      "name": "MSFT Internet Explorer 11 - Computer",
      "purpose": "MSFTInternetExplorer11Computer",
      "scope": "machine",
      "source_backup_path": "GPOs/{ABFB52F2-1560-4100-9103-8C10F57DC9DE}",
      "source_display_name": "MSFT Internet Explorer 11 - Computer",
      "source_gpo_id": "{0655E13C-1744-4738-9965-34FEB87A6430}",
      "source_options": 1,
      "source_package_name": "Windows 10 Version 1809 and Windows Server 2019 Security Baseline.zip",
      "source_package_sha256": "575ddaf39ef364ea6da678e22b0a988ea316eb240f73fbf618092a02647245bc",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2010%20Version%201809%20and%20Windows%20Server%202019%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "50e26f3b336382b1523743ad29b1ba66bf002603f1e21aff1d46ae5cc3565dd1.ipmsgpo",
      "artifact_sha256": "50e26f3b336382b1523743ad29b1ba66bf002603f1e21aff1d46ae5cc3565dd1",
      "artifact_size": 24296,
      "backup_id": "{B9263530-926F-46F3-8382-832C31EC81B5}",
      "baseline_id": "microsoft-windows-server-2019",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Applications",
        "DomainSysvol/GPO/Machine/microsoft",
        "DomainSysvol/GPO/Machine/microsoft/windows nt",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 5012,
          "path": "Backup.xml",
          "sha256": "17cf7f4b4c88ae917f19b5a0bd70caabba5e659dfdfff8a83e89a97ad0202f36"
        },
        {
          "bytes": 612,
          "path": "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit/GptTmpl.inf",
          "sha256": "a2d01aed3eb819470a9e909a29a3a972dd371356d1ad6a8c9843486b2e6eeb47"
        },
        {
          "bytes": 618,
          "path": "bkupInfo.xml",
          "sha256": "2d97bcde607ce4cfaa1d0a37d8fdfd1c2aae0d3cd24b5eb01414f2e7c302aa2b"
        },
        {
          "bytes": 18026,
          "path": "gpreport.xml",
          "sha256": "cb768e55b04dcb31b083dba4015b731356863a557506ea2dd3214a52980f5519"
        }
      ],
      "name": "MSFT Windows 10 1809 and Server 2019 - Domain Security",
      "purpose": "MSFTWindows101809andServer2019DomainSecurity",
      "scope": "domain",
      "source_backup_path": "GPOs/{B9263530-926F-46F3-8382-832C31EC81B5}",
      "source_display_name": "MSFT Windows 10 1809 and Server 2019 - Domain Security",
      "source_gpo_id": "{1D0386B8-0F5B-4698-AF02-CAE2E52A4592}",
      "source_options": 1,
      "source_package_name": "Windows 10 Version 1809 and Windows Server 2019 Security Baseline.zip",
      "source_package_sha256": "575ddaf39ef364ea6da678e22b0a988ea316eb240f73fbf618092a02647245bc",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2010%20Version%201809%20and%20Windows%20Server%202019%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "163770700f6a9ec85d0472e9b681c028413cb4a39a54e087394437d7112a1b0c.ipmsgpo",
      "artifact_sha256": "163770700f6a9ec85d0472e9b681c028413cb4a39a54e087394437d7112a1b0c",
      "artifact_size": 232535,
      "backup_id": "{C92CC433-A4EA-47B1-8B24-6FF732940E0E}",
      "baseline_id": "microsoft-windows-server-2019",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Applications",
        "DomainSysvol/GPO/Machine/Preferences",
        "DomainSysvol/GPO/Machine/Preferences/Registry",
        "DomainSysvol/GPO/Machine/Scripts",
        "DomainSysvol/GPO/Machine/Scripts/Shutdown",
        "DomainSysvol/GPO/Machine/Scripts/Startup",
        "DomainSysvol/GPO/Machine/microsoft",
        "DomainSysvol/GPO/Machine/microsoft/windows nt",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 9303,
          "path": "Backup.xml",
          "sha256": "04db7c2fe95b5010b40ca068537e53171a870dac016d31c9aaf33f870945b494"
        },
        {
          "bytes": 568,
          "path": "DomainSysvol/GPO/Machine/comment.cmtx",
          "sha256": "5e19af7f32ce59c7612a2ed460c0180df0366a42a15d299cf1a269d1bd202641"
        },
        {
          "bytes": 2208,
          "path": "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit/audit.csv",
          "sha256": "29252c1b507bad5363c730b1a51b4032ec3bde603b3aae8d9425fe3785f44685"
        },
        {
          "bytes": 7488,
          "path": "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit/GptTmpl.inf",
          "sha256": "cfad9dd2be132c31a5b7d8024e391df46ec0f75cf700db526e5eab2677a89a0f"
        },
        {
          "bytes": 11090,
          "path": "DomainSysvol/GPO/Machine/registry.pol",
          "sha256": "b20a7a90458c7d04191f1bc3879d180210ed84f2fbfc7e18125d7c32f0494a4a"
        },
        {
          "bytes": 720,
          "path": "DomainSysvol/GPO/User/comment.cmtx",
          "sha256": "0a8282f81b3160402cfbcbfc19ab6664a543df703be83960bb285d18b5263a4f"
        },
        {
          "bytes": 8,
          "path": "DomainSysvol/GPO/User/registry.pol",
          "sha256": "5bb1f21f806938a043563024b13b33d74a2b95b767c5f81bde8456e9d0413a89"
        },
        {
          "bytes": 604,
          "path": "bkupInfo.xml",
          "sha256": "6ec07e640b9efa26b5b74588f111d3938d004c6ac0ba4c07de5dcf1a3839d08f"
        },
        {
          "bytes": 200498,
          "path": "gpreport.xml",
          "sha256": "f671acd2ac40d5adcce39633ab9548cd3370cdbfe9eddb5000c5028152269b13"
        }
      ],
      "name": "MSFT Windows Server 2019 - Member Server",
      "purpose": "MSFTWindowsServer2019MemberServer",
      "scope": "machine",
      "source_backup_path": "GPOs/{C92CC433-A4EA-47B1-8B24-6FF732940E0E}",
      "source_display_name": "MSFT Windows Server 2019 - Member Server",
      "source_gpo_id": "{996B3F87-FC3E-4E1D-9194-77D5C77D5C22}",
      "source_options": 1,
      "source_package_name": "Windows 10 Version 1809 and Windows Server 2019 Security Baseline.zip",
      "source_package_sha256": "575ddaf39ef364ea6da678e22b0a988ea316eb240f73fbf618092a02647245bc",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2010%20Version%201809%20and%20Windows%20Server%202019%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "2c57dd427e9bef5b900c6defc71baecace9c49f19b8be5601c9e9dd6d6c40789.ipmsgpo",
      "artifact_sha256": "2c57dd427e9bef5b900c6defc71baecace9c49f19b8be5601c9e9dd6d6c40789",
      "artifact_size": 24336,
      "backup_id": "{E913422C-4F06-4D37-A739-2CD2B701978E}",
      "baseline_id": "microsoft-windows-server-2019",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Applications",
        "DomainSysvol/GPO/Machine/microsoft",
        "DomainSysvol/GPO/Machine/microsoft/windows nt",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 5067,
          "path": "Backup.xml",
          "sha256": "4452f1fa1808040f2c61611cb1ad0033ca9eed5262fb2687252b955b6576a642"
        },
        {
          "bytes": 901,
          "path": "DomainSysvol/GPO/User/comment.cmtx",
          "sha256": "4626e59f12f72f994ce0a1591e5fbcfb1c83cc60462c35d3dff42f745cb0ea30"
        },
        {
          "bytes": 534,
          "path": "DomainSysvol/GPO/User/registry.pol",
          "sha256": "bdc7178487ef6346e2e4796ac6aae54a2076f950cb541bb4bd88c7c4a6874a96"
        },
        {
          "bytes": 596,
          "path": "bkupInfo.xml",
          "sha256": "f37dfef1a09ce616da15efb99af730c472ab8df159e50e3920cfc9ad52a54789"
        },
        {
          "bytes": 17206,
          "path": "gpreport.xml",
          "sha256": "040c7fadc9c10dbeb2b3b199f3edd87341d5e25f0b6e05117b4703456264dcab"
        }
      ],
      "name": "MSFT Internet Explorer 11 - User",
      "purpose": "MSFTInternetExplorer11User",
      "scope": "user",
      "source_backup_path": "GPOs/{E913422C-4F06-4D37-A739-2CD2B701978E}",
      "source_display_name": "MSFT Internet Explorer 11 - User",
      "source_gpo_id": "{CB222E82-914F-4560-91F1-DEF7A0E964D1}",
      "source_options": 2,
      "source_package_name": "Windows 10 Version 1809 and Windows Server 2019 Security Baseline.zip",
      "source_package_sha256": "575ddaf39ef364ea6da678e22b0a988ea316eb240f73fbf618092a02647245bc",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2010%20Version%201809%20and%20Windows%20Server%202019%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "bdcc9987bb05aa869cad8c023e46a2bb3db4332f37366227a2f5814fc24c8621.ipmsgpo",
      "artifact_sha256": "bdcc9987bb05aa869cad8c023e46a2bb3db4332f37366227a2f5814fc24c8621",
      "artifact_size": 47602,
      "backup_id": "{FEE76283-957E-4B25-9380-2F737E13E972}",
      "baseline_id": "microsoft-windows-server-2019",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 3629,
          "path": "Backup.xml",
          "sha256": "8d90e1fbbfa3e99cc99e4333b2287547729d7beea830ae7e59c0bdb131060464"
        },
        {
          "bytes": 554,
          "path": "DomainSysvol/GPO/Machine/comment.cmtx",
          "sha256": "f4cb5d64e7a8cec20da34b276020efb31262ab81bc325d754578d60f87d5e387"
        },
        {
          "bytes": 4500,
          "path": "DomainSysvol/GPO/Machine/registry.pol",
          "sha256": "39982464cf951a387a45e304fac8fb89972632e52fcbd2b00c584263564dd277"
        },
        {
          "bytes": 621,
          "path": "bkupInfo.xml",
          "sha256": "5d1f4e8d5bc3a1a71195531650e0c334ba35be6c03af6359339abff2a9b6f6a9"
        },
        {
          "bytes": 38266,
          "path": "gpreport.xml",
          "sha256": "01a17250a6191cadffd4d9a036220f0d7f77e6fe93ce400ef8343263d2baa498"
        }
      ],
      "name": "MSFT Windows 10 1809 and Server 2019 - Defender Antivirus",
      "purpose": "MSFTWindows101809andServer2019DefenderAntivirus",
      "scope": "machine",
      "source_backup_path": "GPOs/{FEE76283-957E-4B25-9380-2F737E13E972}",
      "source_display_name": "MSFT Windows 10 1809 and Server 2019 - Defender Antivirus",
      "source_gpo_id": "{25AE1E1D-ED23-40F3-B71F-29B2BD9BB85C}",
      "source_options": 1,
      "source_package_name": "Windows 10 Version 1809 and Windows Server 2019 Security Baseline.zip",
      "source_package_sha256": "575ddaf39ef364ea6da678e22b0a988ea316eb240f73fbf618092a02647245bc",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2010%20Version%201809%20and%20Windows%20Server%202019%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "0c850cec6fb95b6b967e8a0e878b58bf24961d811a6eb3068e82fa917eb60919.ipmsgpo",
      "artifact_sha256": "0c850cec6fb95b6b967e8a0e878b58bf24961d811a6eb3068e82fa917eb60919",
      "artifact_size": 243746,
      "backup_id": "{FEFBD334-CF33-4078-8829-4B00DC1D164B}",
      "baseline_id": "microsoft-windows-server-2019",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Applications",
        "DomainSysvol/GPO/Machine/Preferences",
        "DomainSysvol/GPO/Machine/Preferences/Registry",
        "DomainSysvol/GPO/Machine/Scripts",
        "DomainSysvol/GPO/Machine/Scripts/Shutdown",
        "DomainSysvol/GPO/Machine/Scripts/Startup",
        "DomainSysvol/GPO/Machine/microsoft",
        "DomainSysvol/GPO/Machine/microsoft/windows nt",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 9173,
          "path": "Backup.xml",
          "sha256": "b674c6dc831186c84365a2f23ce30f827fdcb913f7ab39bd81c676a120b69727"
        },
        {
          "bytes": 568,
          "path": "DomainSysvol/GPO/Machine/comment.cmtx",
          "sha256": "5e19af7f32ce59c7612a2ed460c0180df0366a42a15d299cf1a269d1bd202641"
        },
        {
          "bytes": 2603,
          "path": "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit/audit.csv",
          "sha256": "5a0ad97a2b7c4e593f287e68e6cc7cd5631d858968319af7ab69cc1665cb7a04"
        },
        {
          "bytes": 7656,
          "path": "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit/GptTmpl.inf",
          "sha256": "ce96c417ae277e9e61f21b9d98f3499301c5abbec352840d10ec80307e4fd3b1"
        },
        {
          "bytes": 18146,
          "path": "DomainSysvol/GPO/Machine/registry.pol",
          "sha256": "1bf3fac9f7c3666c8e99a254eaf9f48e9658fae36995849fb66cf1f8824118b3"
        },
        {
          "bytes": 720,
          "path": "DomainSysvol/GPO/User/comment.cmtx",
          "sha256": "0a8282f81b3160402cfbcbfc19ab6664a543df703be83960bb285d18b5263a4f"
        },
        {
          "bytes": 8,
          "path": "DomainSysvol/GPO/User/registry.pol",
          "sha256": "5bb1f21f806938a043563024b13b33d74a2b95b767c5f81bde8456e9d0413a89"
        },
        {
          "bytes": 608,
          "path": "bkupInfo.xml",
          "sha256": "2af41c1a8e2019a7f14d27150f69d7c1fa85de982ebc8b991936ff6e9d9f8008"
        },
        {
          "bytes": 204216,
          "path": "gpreport.xml",
          "sha256": "36909ec0c79e035323a37f67c30d20d3acdde0a837a7e117f401ce86700c918b"
        }
      ],
      "name": "MSFT Windows Server 2019 - Domain Controller",
      "purpose": "MSFTWindowsServer2019DomainController",
      "scope": "machine",
      "source_backup_path": "GPOs/{FEFBD334-CF33-4078-8829-4B00DC1D164B}",
      "source_display_name": "MSFT Windows Server 2019 - Domain Controller",
      "source_gpo_id": "{E911AD4D-9C89-4BE3-AE6E-269D734C2330}",
      "source_options": 1,
      "source_package_name": "Windows 10 Version 1809 and Windows Server 2019 Security Baseline.zip",
      "source_package_sha256": "575ddaf39ef364ea6da678e22b0a988ea316eb240f73fbf618092a02647245bc",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%2010%20Version%201809%20and%20Windows%20Server%202019%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "9ea14352f7f32fdcf2cf18272ab16100414e139090c97635d04c0501240f102d.ipmsgpo",
      "artifact_sha256": "9ea14352f7f32fdcf2cf18272ab16100414e139090c97635d04c0501240f102d",
      "artifact_size": 354302,
      "backup_id": "{0A531EAC-7B92-4E02-9877-1FB7CBE41398}",
      "baseline_id": "microsoft-windows-server-2022",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Applications",
        "DomainSysvol/GPO/Machine/Scripts",
        "DomainSysvol/GPO/Machine/Scripts/Shutdown",
        "DomainSysvol/GPO/Machine/Scripts/Startup",
        "DomainSysvol/GPO/Machine/microsoft",
        "DomainSysvol/GPO/Machine/microsoft/windows nt",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 6149,
          "path": "Backup.xml",
          "sha256": "e51963b47fbe138a71cd4548497f028d7c34493bd5337e9d8b4a88aa4f7a9b52"
        },
        {
          "bytes": 555,
          "path": "DomainSysvol/GPO/Machine/comment.cmtx",
          "sha256": "e6d7b0805b21144958f6b70b5273bd3eab96950b59fbcb1654654f4924cbd35c"
        },
        {
          "bytes": 142,
          "path": "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit/GptTmpl.inf",
          "sha256": "07cba636ed9c1c30c4a4c228e555151f1fc43f7bfc941cbb221ed67297ea3dbc"
        },
        {
          "bytes": 25970,
          "path": "DomainSysvol/GPO/Machine/registry.pol",
          "sha256": "8a5b1628731d7516b4d45144cef6c9aab6e823b62bcd4db226e83c5820e088cc"
        },
        {
          "bytes": 600,
          "path": "bkupInfo.xml",
          "sha256": "f082a0c00dd593b96c8bba4932b79f6105be8b953e585aaa388b364248d25f2b"
        },
        {
          "bytes": 320850,
          "path": "gpreport.xml",
          "sha256": "44b1388c2a2cc9dfafca45e69efaf7a2f1e0351a63182d70f802b65bc4ef5563"
        }
      ],
      "name": "MSFT Internet Explorer 11 - Computer",
      "purpose": "MSFTInternetExplorer11Computer",
      "scope": "machine",
      "source_backup_path": "Windows Server-2022-Security-Baseline-FINAL/GPOs/{0A531EAC-7B92-4E02-9877-1FB7CBE41398}",
      "source_display_name": "MSFT Internet Explorer 11 - Computer",
      "source_gpo_id": "{D5398278-ABE5-4648-921E-D68A15AF59E9}",
      "source_options": 1,
      "source_package_name": "Windows Server 2022 Security Baseline.zip",
      "source_package_sha256": "49590cc694626d171fc934fafea6494f13ecd3843086704b7a5b98355909b8e0",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%20Server%202022%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "1052c09a3ed562da7031a36b963f59d531d83f39076818f5d6bc560338f703e5.ipmsgpo",
      "artifact_sha256": "1052c09a3ed562da7031a36b963f59d531d83f39076818f5d6bc560338f703e5",
      "artifact_size": 236647,
      "backup_id": "{20FAD6FB-7C6D-496E-801C-0434769847FF}",
      "baseline_id": "microsoft-windows-server-2022",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Applications",
        "DomainSysvol/GPO/Machine/Preferences",
        "DomainSysvol/GPO/Machine/Preferences/Registry",
        "DomainSysvol/GPO/Machine/Scripts",
        "DomainSysvol/GPO/Machine/Scripts/Shutdown",
        "DomainSysvol/GPO/Machine/Scripts/Startup",
        "DomainSysvol/GPO/Machine/microsoft",
        "DomainSysvol/GPO/Machine/microsoft/windows nt",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 9304,
          "path": "Backup.xml",
          "sha256": "40e95c9e230370274a44b66688c16c345c594cdef4088386fdb2c05a7a4986ca"
        },
        {
          "bytes": 547,
          "path": "DomainSysvol/GPO/Machine/comment.cmtx",
          "sha256": "624d822e257ebc6def32f1efa8d3ac0531b2fd76bbc016190e2f0730d90b405f"
        },
        {
          "bytes": 2208,
          "path": "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit/audit.csv",
          "sha256": "29252c1b507bad5363c730b1a51b4032ec3bde603b3aae8d9425fe3785f44685"
        },
        {
          "bytes": 7088,
          "path": "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit/GptTmpl.inf",
          "sha256": "e9fa8208aec6b2fe1f048c61c2b6667cc2b01fbc29f48ed84e0d341e8d0a9c08"
        },
        {
          "bytes": 11282,
          "path": "DomainSysvol/GPO/Machine/registry.pol",
          "sha256": "953bae8c14f964d6b196ffeaa0287305f9efefe009d431c076247d6d8bfec78b"
        },
        {
          "bytes": 720,
          "path": "DomainSysvol/GPO/User/comment.cmtx",
          "sha256": "0a8282f81b3160402cfbcbfc19ab6664a543df703be83960bb285d18b5263a4f"
        },
        {
          "bytes": 8,
          "path": "DomainSysvol/GPO/User/registry.pol",
          "sha256": "5bb1f21f806938a043563024b13b33d74a2b95b767c5f81bde8456e9d0413a89"
        },
        {
          "bytes": 604,
          "path": "bkupInfo.xml",
          "sha256": "84539557c8bcd532dbc8132d9bbcb21512561111957fdb53b7340888edcd1967"
        },
        {
          "bytes": 204838,
          "path": "gpreport.xml",
          "sha256": "71744ab3c0e9f72c57fedcc3544ef8a234f4cbab883ce1d9d551bf0b6402afa4"
        }
      ],
      "name": "MSFT Windows Server 2022 - Member Server",
      "purpose": "MSFTWindowsServer2022MemberServer",
      "scope": "machine",
      "source_backup_path": "Windows Server-2022-Security-Baseline-FINAL/GPOs/{20FAD6FB-7C6D-496E-801C-0434769847FF}",
      "source_display_name": "MSFT Windows Server 2022 - Member Server",
      "source_gpo_id": "{FA0F36D8-14CE-4D94-90F7-66A01DDB07C4}",
      "source_options": 1,
      "source_package_name": "Windows Server 2022 Security Baseline.zip",
      "source_package_sha256": "49590cc694626d171fc934fafea6494f13ecd3843086704b7a5b98355909b8e0",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%20Server%202022%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "2f2619a4592051ff83c4e0d2bf1da95518481aef8ab91484a73c8583f5c38f6e.ipmsgpo",
      "artifact_sha256": "2f2619a4592051ff83c4e0d2bf1da95518481aef8ab91484a73c8583f5c38f6e",
      "artifact_size": 32352,
      "backup_id": "{64059F15-E999-4E2F-865D-C0766B886266}",
      "baseline_id": "microsoft-windows-server-2022",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Scripts",
        "DomainSysvol/GPO/Machine/Scripts/Shutdown",
        "DomainSysvol/GPO/Machine/Scripts/Startup",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 4470,
          "path": "Backup.xml",
          "sha256": "df5a7afbaaa55a09479c3dc82e49f752bbe1c30535939fe9785d393b1d45146c"
        },
        {
          "bytes": 549,
          "path": "DomainSysvol/GPO/Machine/comment.cmtx",
          "sha256": "94f49ee096c38f34ddf86a3d864661da5a39cca6a641ce5db6c159bf106d8e01"
        },
        {
          "bytes": 1034,
          "path": "DomainSysvol/GPO/Machine/registry.pol",
          "sha256": "1b24281950bda792d454d3887a9ee51d63ee8b6cdf8b883da6695b41d7ab45b2"
        },
        {
          "bytes": 621,
          "path": "bkupInfo.xml",
          "sha256": "2c3935bec77d6598d3b90ed5f5efa9d41a81f1f8f32a0f2d8744f6bca491ad52"
        },
        {
          "bytes": 25646,
          "path": "gpreport.xml",
          "sha256": "e876f52e7a58751db2c24f53eeb4d6c359a971446c44d9e6e6bf5a8fb87c9250"
        }
      ],
      "name": "MSFT Windows Server 2022 - Member Server Credential Guard",
      "purpose": "MSFTWindowsServer2022MemberServerCredentialGuard",
      "scope": "machine",
      "source_backup_path": "Windows Server-2022-Security-Baseline-FINAL/GPOs/{64059F15-E999-4E2F-865D-C0766B886266}",
      "source_display_name": "MSFT Windows Server 2022 - Member Server Credential Guard",
      "source_gpo_id": "{44695B91-00D9-40B4-99E2-550960065DE7}",
      "source_options": 1,
      "source_package_name": "Windows Server 2022 Security Baseline.zip",
      "source_package_sha256": "49590cc694626d171fc934fafea6494f13ecd3843086704b7a5b98355909b8e0",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%20Server%202022%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "98665eaf51b721d21bf0f4a4fa8dac47679b7a1a85acf5765c3a072a90b8306f.ipmsgpo",
      "artifact_sha256": "98665eaf51b721d21bf0f4a4fa8dac47679b7a1a85acf5765c3a072a90b8306f",
      "artifact_size": 31647,
      "backup_id": "{8104AFEB-D49C-4125-92F9-748F50407A6B}",
      "baseline_id": "microsoft-windows-server-2022",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 3726,
          "path": "Backup.xml",
          "sha256": "ba246322f78163feebd7bc04638a4df08e86eb87c113b70852722087040ed5be"
        },
        {
          "bytes": 549,
          "path": "DomainSysvol/GPO/Machine/comment.cmtx",
          "sha256": "94f49ee096c38f34ddf86a3d864661da5a39cca6a641ce5db6c159bf106d8e01"
        },
        {
          "bytes": 1034,
          "path": "DomainSysvol/GPO/Machine/registry.pol",
          "sha256": "73d6349571f07ab0f7b83086a8badddcdecb43d2f90dfc77b0f2a33d2a35fef9"
        },
        {
          "bytes": 638,
          "path": "bkupInfo.xml",
          "sha256": "58c5a193e9bc719f986b9a66807288cb0f19cab681081ef0ab4c9c6939040517"
        },
        {
          "bytes": 25668,
          "path": "gpreport.xml",
          "sha256": "2772192c48335df0b336c01bbe59db0b1bd76b9ae7232a407aa3ba02aa1ff553"
        }
      ],
      "name": "MSFT Windows Server 2022 - Domain Controller Virtualization Based Security",
      "purpose": "MSFTWindowsServer2022DomainControllerVirtualizationBasedSecurity",
      "scope": "machine",
      "source_backup_path": "Windows Server-2022-Security-Baseline-FINAL/GPOs/{8104AFEB-D49C-4125-92F9-748F50407A6B}",
      "source_display_name": "MSFT Windows Server 2022 - Domain Controller Virtualization Based Security",
      "source_gpo_id": "{44ED78EF-5F5B-40A1-B332-B4793122028D}",
      "source_options": 1,
      "source_package_name": "Windows Server 2022 Security Baseline.zip",
      "source_package_sha256": "49590cc694626d171fc934fafea6494f13ecd3843086704b7a5b98355909b8e0",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%20Server%202022%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "dc1da08f2631b555853d71481852ad9e4bfe5760d01175412bbe9d62cbc6e891.ipmsgpo",
      "artifact_sha256": "dc1da08f2631b555853d71481852ad9e4bfe5760d01175412bbe9d62cbc6e891",
      "artifact_size": 58948,
      "backup_id": "{966B53AB-4B25-43F6-BACA-9738F0053331}",
      "baseline_id": "microsoft-windows-server-2022",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 3619,
          "path": "Backup.xml",
          "sha256": "cb1735733d1b9a9346f76b4cd08a7bc94e15a7fa081048563cafcf0551eca27e"
        },
        {
          "bytes": 554,
          "path": "DomainSysvol/GPO/Machine/comment.cmtx",
          "sha256": "f4cb5d64e7a8cec20da34b276020efb31262ab81bc325d754578d60f87d5e387"
        },
        {
          "bytes": 5618,
          "path": "DomainSysvol/GPO/Machine/registry.pol",
          "sha256": "7548afdda19fd9d9ce59315e501388b848a24eac8dcbde140a5b03e2a69883e5"
        },
        {
          "bytes": 609,
          "path": "bkupInfo.xml",
          "sha256": "4a3735579b7a25a20ac9aea87ea4a36b353008294965df20416394d02daa2b53"
        },
        {
          "bytes": 48516,
          "path": "gpreport.xml",
          "sha256": "fcc8e730c8f103b6f02377189f45048a14c75a4ff879ec47ece9fe8e196ad17c"
        }
      ],
      "name": "MSFT Windows Server 2022 - Defender Antivirus",
      "purpose": "MSFTWindowsServer2022DefenderAntivirus",
      "scope": "machine",
      "source_backup_path": "Windows Server-2022-Security-Baseline-FINAL/GPOs/{966B53AB-4B25-43F6-BACA-9738F0053331}",
      "source_display_name": "MSFT Windows Server 2022 - Defender Antivirus",
      "source_gpo_id": "{38D30C9A-6468-4627-9013-0EB968775C75}",
      "source_options": 1,
      "source_package_name": "Windows Server 2022 Security Baseline.zip",
      "source_package_sha256": "49590cc694626d171fc934fafea6494f13ecd3843086704b7a5b98355909b8e0",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%20Server%202022%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "e8a8ea69c81b5df036c0524dd159e06666774e409c7b257ba91b72776beb20c7.ipmsgpo",
      "artifact_sha256": "e8a8ea69c81b5df036c0524dd159e06666774e409c7b257ba91b72776beb20c7",
      "artifact_size": 24970,
      "backup_id": "{AAC7C960-51D3-4BEE-89BD-7FB10361AA16}",
      "baseline_id": "microsoft-windows-server-2022",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Applications",
        "DomainSysvol/GPO/Machine/Scripts",
        "DomainSysvol/GPO/Machine/Scripts/Shutdown",
        "DomainSysvol/GPO/Machine/Scripts/Startup",
        "DomainSysvol/GPO/Machine/microsoft",
        "DomainSysvol/GPO/Machine/microsoft/windows nt",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 5764,
          "path": "Backup.xml",
          "sha256": "0a91a7c93f6d84a158cb492a9a6578ec26c2735501b9312313ffd344934b72b9"
        },
        {
          "bytes": 514,
          "path": "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit/GptTmpl.inf",
          "sha256": "049c9f05de9965e35d65cfa0c186e4598fe135d1876acf7873940fc81ea47df2"
        },
        {
          "bytes": 606,
          "path": "bkupInfo.xml",
          "sha256": "0937b068096e94a49dd9d29563d454c4d297a11f67c93f9512ae0851cb9d70b2"
        },
        {
          "bytes": 18058,
          "path": "gpreport.xml",
          "sha256": "c72f34e0c0596bb9883d2a1cd60cdd4fa11778d454af038f5f0e76c91f36b330"
        }
      ],
      "name": "MSFT Windows Server 2022 - Domain Security",
      "purpose": "MSFTWindowsServer2022DomainSecurity",
      "scope": "domain",
      "source_backup_path": "Windows Server-2022-Security-Baseline-FINAL/GPOs/{AAC7C960-51D3-4BEE-89BD-7FB10361AA16}",
      "source_display_name": "MSFT Windows Server 2022 - Domain Security",
      "source_gpo_id": "{48572E0B-3938-4934-BFC7-828190868BAE}",
      "source_options": 1,
      "source_package_name": "Windows Server 2022 Security Baseline.zip",
      "source_package_sha256": "49590cc694626d171fc934fafea6494f13ecd3843086704b7a5b98355909b8e0",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%20Server%202022%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "d4ca07dd044419c5c6fcdab58174c37200c9a15ba95afc332a39119b70e53bb0.ipmsgpo",
      "artifact_sha256": "d4ca07dd044419c5c6fcdab58174c37200c9a15ba95afc332a39119b70e53bb0",
      "artifact_size": 25490,
      "backup_id": "{BEA08B79-482E-4216-B5DE-8528F3688DD5}",
      "baseline_id": "microsoft-windows-server-2022",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Applications",
        "DomainSysvol/GPO/Machine/microsoft",
        "DomainSysvol/GPO/Machine/microsoft/windows nt",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 5069,
          "path": "Backup.xml",
          "sha256": "7ed7aaeb86a374475dd3fa72bf8ddb8801bcb01419fd2550b4189d2ff249c852"
        },
        {
          "bytes": 901,
          "path": "DomainSysvol/GPO/User/comment.cmtx",
          "sha256": "4626e59f12f72f994ce0a1591e5fbcfb1c83cc60462c35d3dff42f745cb0ea30"
        },
        {
          "bytes": 534,
          "path": "DomainSysvol/GPO/User/registry.pol",
          "sha256": "bdc7178487ef6346e2e4796ac6aae54a2076f950cb541bb4bd88c7c4a6874a96"
        },
        {
          "bytes": 596,
          "path": "bkupInfo.xml",
          "sha256": "5c261c0afc516bc609425ddd1e9e79448fc130ddcbecbd428e8b0d7cdd0a141f"
        },
        {
          "bytes": 18358,
          "path": "gpreport.xml",
          "sha256": "bea691c7277039b00d5e814220717a1f8e2bc8fe344e4aaf3143fba5a5525dea"
        }
      ],
      "name": "MSFT Internet Explorer 11 - User",
      "purpose": "MSFTInternetExplorer11User",
      "scope": "user",
      "source_backup_path": "Windows Server-2022-Security-Baseline-FINAL/GPOs/{BEA08B79-482E-4216-B5DE-8528F3688DD5}",
      "source_display_name": "MSFT Internet Explorer 11 - User",
      "source_gpo_id": "{582D31BD-8974-43C8-B88B-FC18B4254E87}",
      "source_options": 2,
      "source_package_name": "Windows Server 2022 Security Baseline.zip",
      "source_package_sha256": "49590cc694626d171fc934fafea6494f13ecd3843086704b7a5b98355909b8e0",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%20Server%202022%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "794ff4ec6e7a2dc12a2fb5fbecb485fb34310cc1c63a63624cc367aba3d7d184.ipmsgpo",
      "artifact_sha256": "794ff4ec6e7a2dc12a2fb5fbecb485fb34310cc1c63a63624cc367aba3d7d184",
      "artifact_size": 249856,
      "backup_id": "{E2B8214C-729F-4324-A876-F067E58B740B}",
      "baseline_id": "microsoft-windows-server-2022",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Applications",
        "DomainSysvol/GPO/Machine/Preferences",
        "DomainSysvol/GPO/Machine/Preferences/Registry",
        "DomainSysvol/GPO/Machine/Scripts",
        "DomainSysvol/GPO/Machine/Scripts/Shutdown",
        "DomainSysvol/GPO/Machine/Scripts/Startup",
        "DomainSysvol/GPO/Machine/microsoft",
        "DomainSysvol/GPO/Machine/microsoft/windows nt",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 9175,
          "path": "Backup.xml",
          "sha256": "db1ecdbe7ab1cd09e19e62625ac8566e1396394d428931a63012bd221753f91d"
        },
        {
          "bytes": 547,
          "path": "DomainSysvol/GPO/Machine/comment.cmtx",
          "sha256": "624d822e257ebc6def32f1efa8d3ac0531b2fd76bbc016190e2f0730d90b405f"
        },
        {
          "bytes": 2776,
          "path": "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit/audit.csv",
          "sha256": "740b924f9e9bbd71c939a549c39600bd1ad97188192d679d9b331b2a5567c50c"
        },
        {
          "bytes": 7306,
          "path": "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit/GptTmpl.inf",
          "sha256": "e4a3f7a28f42e17069a2672ca0ae30fba2f54160b05fa847ca85164d028d7a05"
        },
        {
          "bytes": 19598,
          "path": "DomainSysvol/GPO/Machine/registry.pol",
          "sha256": "61c1e4e265ff2fceaba321d486f4789466d804974f9efe097690c32b858f2416"
        },
        {
          "bytes": 720,
          "path": "DomainSysvol/GPO/User/comment.cmtx",
          "sha256": "0a8282f81b3160402cfbcbfc19ab6664a543df703be83960bb285d18b5263a4f"
        },
        {
          "bytes": 8,
          "path": "DomainSysvol/GPO/User/registry.pol",
          "sha256": "5bb1f21f806938a043563024b13b33d74a2b95b767c5f81bde8456e9d0413a89"
        },
        {
          "bytes": 608,
          "path": "bkupInfo.xml",
          "sha256": "2891c52b7cee3f1d74440fcd1c1d469e44e107e585fc5aff5d4c2ca92bd84f8a"
        },
        {
          "bytes": 209070,
          "path": "gpreport.xml",
          "sha256": "6363194fa4d310cf6175f1ebc3e43654f79630c5a8d4cab99dc9da9390d5e129"
        }
      ],
      "name": "MSFT Windows Server 2022 - Domain Controller",
      "purpose": "MSFTWindowsServer2022DomainController",
      "scope": "machine",
      "source_backup_path": "Windows Server-2022-Security-Baseline-FINAL/GPOs/{E2B8214C-729F-4324-A876-F067E58B740B}",
      "source_display_name": "MSFT Windows Server 2022 - Domain Controller",
      "source_gpo_id": "{FFB4098C-1E38-47B9-87BD-135ABB03590A}",
      "source_options": 1,
      "source_package_name": "Windows Server 2022 Security Baseline.zip",
      "source_package_sha256": "49590cc694626d171fc934fafea6494f13ecd3843086704b7a5b98355909b8e0",
      "source_package_url": "https://download.microsoft.com/download/8/5/c/85c25433-a1b0-4ffa-9429-7e023e7da8d8/Windows%20Server%202022%20Security%20Baseline.zip"
    },
    {
      "artifact_filename": "e956bc218c4d49af5846f1405efbf34d687d7edea598976b8610718b66776cbe.ipmsgpo",
      "artifact_sha256": "e956bc218c4d49af5846f1405efbf34d687d7edea598976b8610718b66776cbe",
      "artifact_size": 300321,
      "backup_id": "{066B7FF5-BF2B-4B1B-8A92-2A83B8619444}",
      "baseline_id": "microsoft-windows-server-2025",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Applications",
        "DomainSysvol/GPO/Machine/Preferences",
        "DomainSysvol/GPO/Machine/Preferences/Registry",
        "DomainSysvol/GPO/Machine/Scripts",
        "DomainSysvol/GPO/Machine/Scripts/Shutdown",
        "DomainSysvol/GPO/Machine/Scripts/Startup",
        "DomainSysvol/GPO/Machine/microsoft",
        "DomainSysvol/GPO/Machine/microsoft/windows nt",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 9304,
          "path": "Backup.xml",
          "sha256": "18292473b59733729d610efd61d2d9b4fd969a5a34dda1139eeefdcf1087b2db"
        },
        {
          "bytes": 790,
          "path": "DomainSysvol/GPO/Machine/comment.cmtx",
          "sha256": "33242c22925d862187a44daaca8f592cbecb1174d1966dd966ffa060a20c13d5"
        },
        {
          "bytes": 2313,
          "path": "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit/audit.csv",
          "sha256": "e141c09714db2465578db74ef36198d46f155283e1db13b28c8eb7805f9a38b9"
        },
        {
          "bytes": 7488,
          "path": "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit/GptTmpl.inf",
          "sha256": "4403795c0f1eb374b285592a0589a5addfa6af3c5b33490c35595037513ba8e8"
        },
        {
          "bytes": 18540,
          "path": "DomainSysvol/GPO/Machine/registry.pol",
          "sha256": "d134f946e515b79df21b09d22fd92b2c683d03d18a0aaeb20234af6a403304a0"
        },
        {
          "bytes": 720,
          "path": "DomainSysvol/GPO/User/comment.cmtx",
          "sha256": "0a8282f81b3160402cfbcbfc19ab6664a543df703be83960bb285d18b5263a4f"
        },
        {
          "bytes": 8,
          "path": "DomainSysvol/GPO/User/registry.pol",
          "sha256": "5bb1f21f806938a043563024b13b33d74a2b95b767c5f81bde8456e9d0413a89"
        },
        {
          "bytes": 610,
          "path": "bkupInfo.xml",
          "sha256": "d66c27c8fc80afe7c073e43a01049abb4463686572b843efed6ad688a744f1c9"
        },
        {
          "bytes": 260500,
          "path": "gpreport.xml",
          "sha256": "9babcfcd956e89e7d446d5aeefcf623b7088b9376b9cee5cb50f01de1b701327"
        }
      ],
      "name": "MSFT Windows Server 2025 v2602 - Member Server",
      "purpose": "MSFTWindowsServer2025v2602MemberServer",
      "scope": "machine",
      "source_backup_path": "Windows Server 2025 Security Baseline - 2602/GPOs/{066B7FF5-BF2B-4B1B-8A92-2A83B8619444}",
      "source_display_name": "MSFT Windows Server 2025 v2602 - Member Server",
      "source_gpo_id": "{66D20891-6858-43DF-B3F6-CC7BE11C7EC1}",
      "source_options": 1,
      "source_package_name": "Windows Server 2025 Security Baseline - 2602.zip",
      "source_package_sha256": "a66dffbe2622c3c4dd70e44a7f2080f362fb2d6f9208c50678671cbb046a286f",
      "source_package_url": "https://download.microsoft.com/download/e99be2d2-e077-4986-a06b-6078051999dd/Windows%20Server%202025%20Security%20Baseline%20-%202602.zip"
    },
    {
      "artifact_filename": "1847fa24cf81e9bd0e57ac7d87148c7bb7f4f7253df10606695bb24b2a2484c7.ipmsgpo",
      "artifact_sha256": "1847fa24cf81e9bd0e57ac7d87148c7bb7f4f7253df10606695bb24b2a2484c7",
      "artifact_size": 355463,
      "backup_id": "{2E1948EE-56EE-45A1-9473-D5A4C2153E5F}",
      "baseline_id": "microsoft-windows-server-2025",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Applications",
        "DomainSysvol/GPO/Machine/Scripts",
        "DomainSysvol/GPO/Machine/Scripts/Shutdown",
        "DomainSysvol/GPO/Machine/Scripts/Startup",
        "DomainSysvol/GPO/Machine/microsoft",
        "DomainSysvol/GPO/Machine/microsoft/windows nt",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 6150,
          "path": "Backup.xml",
          "sha256": "ec10e55fbf7018a6bc74f4903312e13870d52ba725d68a61e9ee863e6acae57c"
        },
        {
          "bytes": 555,
          "path": "DomainSysvol/GPO/Machine/comment.cmtx",
          "sha256": "e6d7b0805b21144958f6b70b5273bd3eab96950b59fbcb1654654f4924cbd35c"
        },
        {
          "bytes": 142,
          "path": "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit/GptTmpl.inf",
          "sha256": "07cba636ed9c1c30c4a4c228e555151f1fc43f7bfc941cbb221ed67297ea3dbc"
        },
        {
          "bytes": 26168,
          "path": "DomainSysvol/GPO/Machine/registry.pol",
          "sha256": "b13fd26fe01a1dbff1079308180c35b6daf8254f3b9826837629fa80f9c9fe4a"
        },
        {
          "bytes": 600,
          "path": "bkupInfo.xml",
          "sha256": "611026571308f6b80f818363831eef6fe3a5fd872fa6ce54cbf2f3dc55d97d09"
        },
        {
          "bytes": 321812,
          "path": "gpreport.xml",
          "sha256": "bb560824271d3b6c3f76561160d4de84d39633af6b2478cfa31521b2ec9bc543"
        }
      ],
      "name": "MSFT Internet Explorer 11 - Computer",
      "purpose": "MSFTInternetExplorer11Computer",
      "scope": "machine",
      "source_backup_path": "Windows Server 2025 Security Baseline - 2602/GPOs/{2E1948EE-56EE-45A1-9473-D5A4C2153E5F}",
      "source_display_name": "MSFT Internet Explorer 11 - Computer",
      "source_gpo_id": "{D5398278-ABE5-4648-921E-D68A15AF59E9}",
      "source_options": 1,
      "source_package_name": "Windows Server 2025 Security Baseline - 2602.zip",
      "source_package_sha256": "a66dffbe2622c3c4dd70e44a7f2080f362fb2d6f9208c50678671cbb046a286f",
      "source_package_url": "https://download.microsoft.com/download/e99be2d2-e077-4986-a06b-6078051999dd/Windows%20Server%202025%20Security%20Baseline%20-%202602.zip"
    },
    {
      "artifact_filename": "a8871375d0ae7aa0f766bb2e446fbe5248d0f58a91c874c34dd1a6a0ac800539.ipmsgpo",
      "artifact_sha256": "a8871375d0ae7aa0f766bb2e446fbe5248d0f58a91c874c34dd1a6a0ac800539",
      "artifact_size": 24719,
      "backup_id": "{40CF40AD-F1B2-433F-A5C9-032DB7424608}",
      "baseline_id": "microsoft-windows-server-2025",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Applications",
        "DomainSysvol/GPO/Machine/Scripts",
        "DomainSysvol/GPO/Machine/Scripts/Shutdown",
        "DomainSysvol/GPO/Machine/Scripts/Startup",
        "DomainSysvol/GPO/Machine/microsoft",
        "DomainSysvol/GPO/Machine/microsoft/windows nt",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 5771,
          "path": "Backup.xml",
          "sha256": "e8cc6095e6470c492628526a8d0b2a4da41493d0e000ea1430c4cc1c99f65590"
        },
        {
          "bytes": 612,
          "path": "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit/GptTmpl.inf",
          "sha256": "3e1f203be9762b69ad6098bab187654aca8b7ee4c923d7e67e7aa10f4f57feca"
        },
        {
          "bytes": 612,
          "path": "bkupInfo.xml",
          "sha256": "369b502de28aeb7be429b2627a168b9558cc5eaa710104395a36ad988dcfc97a"
        },
        {
          "bytes": 17696,
          "path": "gpreport.xml",
          "sha256": "34d15669bf40413676f26c9b8a343791699912528b892a1431ff88807f8dd270"
        }
      ],
      "name": "MSFT Windows Server 2025 v2602 - Domain Security",
      "purpose": "MSFTWindowsServer2025v2602DomainSecurity",
      "scope": "domain",
      "source_backup_path": "Windows Server 2025 Security Baseline - 2602/GPOs/{40CF40AD-F1B2-433F-A5C9-032DB7424608}",
      "source_display_name": "MSFT Windows Server 2025 v2602 - Domain Security",
      "source_gpo_id": "{5BC11007-75B1-49A3-A74A-30DF2E4ACB74}",
      "source_options": 1,
      "source_package_name": "Windows Server 2025 Security Baseline - 2602.zip",
      "source_package_sha256": "a66dffbe2622c3c4dd70e44a7f2080f362fb2d6f9208c50678671cbb046a286f",
      "source_package_url": "https://download.microsoft.com/download/e99be2d2-e077-4986-a06b-6078051999dd/Windows%20Server%202025%20Security%20Baseline%20-%202602.zip"
    },
    {
      "artifact_filename": "340cccbf3d7810b2bdd45b09e337a9f0c9acece5bcd960b4cd011c2b78185986.ipmsgpo",
      "artifact_sha256": "340cccbf3d7810b2bdd45b09e337a9f0c9acece5bcd960b4cd011c2b78185986",
      "artifact_size": 41337,
      "backup_id": "{5DCDD718-EB35-4D88-9E9A-2B936D7B8A4B}",
      "baseline_id": "microsoft-windows-server-2025",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Scripts",
        "DomainSysvol/GPO/Machine/Scripts/Shutdown",
        "DomainSysvol/GPO/Machine/Scripts/Startup",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 4477,
          "path": "Backup.xml",
          "sha256": "2058e70de07579721c3084ac39a2430519fbce5a2e89492c74370ae7155ebe53"
        },
        {
          "bytes": 549,
          "path": "DomainSysvol/GPO/Machine/comment.cmtx",
          "sha256": "94f49ee096c38f34ddf86a3d864661da5a39cca6a641ce5db6c159bf106d8e01"
        },
        {
          "bytes": 1392,
          "path": "DomainSysvol/GPO/Machine/registry.pol",
          "sha256": "02d86f726467f87e67903886b4b21fdcbc382d0ce4db6f9ab30d0c93d17fb196"
        },
        {
          "bytes": 627,
          "path": "bkupInfo.xml",
          "sha256": "5bed7052843c675b1ab38db123cb72d8e933fbd9b80c664e715dcd9e1afcb4fa"
        },
        {
          "bytes": 34260,
          "path": "gpreport.xml",
          "sha256": "3db976c09554090843f25c4577df3161ff58b0f52e584c98b38eb74b8da52ee0"
        }
      ],
      "name": "MSFT Windows Server 2025 v2602 - Member Server Credential Guard",
      "purpose": "MSFTWindowsServer2025v2602MemberServerCredentialGuard",
      "scope": "machine",
      "source_backup_path": "Windows Server 2025 Security Baseline - 2602/GPOs/{5DCDD718-EB35-4D88-9E9A-2B936D7B8A4B}",
      "source_display_name": "MSFT Windows Server 2025 v2602 - Member Server Credential Guard",
      "source_gpo_id": "{1F86A1DB-484F-40B9-BA64-14E3676B8806}",
      "source_options": 1,
      "source_package_name": "Windows Server 2025 Security Baseline - 2602.zip",
      "source_package_sha256": "a66dffbe2622c3c4dd70e44a7f2080f362fb2d6f9208c50678671cbb046a286f",
      "source_package_url": "https://download.microsoft.com/download/e99be2d2-e077-4986-a06b-6078051999dd/Windows%20Server%202025%20Security%20Baseline%20-%202602.zip"
    },
    {
      "artifact_filename": "670d76d69de249b30503d2035a73044c0ffd222ffe9fac19553b7fb54c23928b.ipmsgpo",
      "artifact_sha256": "670d76d69de249b30503d2035a73044c0ffd222ffe9fac19553b7fb54c23928b",
      "artifact_size": 310588,
      "backup_id": "{88603F56-DC8F-4132-8A8C-8FE5EB0B4B1A}",
      "baseline_id": "microsoft-windows-server-2025",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Applications",
        "DomainSysvol/GPO/Machine/Preferences",
        "DomainSysvol/GPO/Machine/Preferences/Registry",
        "DomainSysvol/GPO/Machine/Scripts",
        "DomainSysvol/GPO/Machine/Scripts/Shutdown",
        "DomainSysvol/GPO/Machine/Scripts/Startup",
        "DomainSysvol/GPO/Machine/microsoft",
        "DomainSysvol/GPO/Machine/microsoft/windows nt",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 9328,
          "path": "Backup.xml",
          "sha256": "c2059b9d474300c1e7cc4471998d78658652abb3741f0113e517a1afba246cbc"
        },
        {
          "bytes": 859,
          "path": "DomainSysvol/GPO/Machine/comment.cmtx",
          "sha256": "dd0002ec38677cbbd6c7b9c99845c52cbd1ac7d467675a305119ffcfce01fbf2"
        },
        {
          "bytes": 2893,
          "path": "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit/audit.csv",
          "sha256": "3d6fe0320db0d099ef939372f3477628ebe9e920951e0e6cb94459ddf271a92a"
        },
        {
          "bytes": 7880,
          "path": "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit/GptTmpl.inf",
          "sha256": "a0702b0010e54fd16afdad758fee35157c28f82cbbe28e66f69a3a8ea6034ef7"
        },
        {
          "bytes": 25758,
          "path": "DomainSysvol/GPO/Machine/registry.pol",
          "sha256": "9cdef3d58980c144d7cc6735e984dff75b62a87bad3a3203df253c6eea20714f"
        },
        {
          "bytes": 720,
          "path": "DomainSysvol/GPO/User/comment.cmtx",
          "sha256": "0a8282f81b3160402cfbcbfc19ab6664a543df703be83960bb285d18b5263a4f"
        },
        {
          "bytes": 8,
          "path": "DomainSysvol/GPO/User/registry.pol",
          "sha256": "5bb1f21f806938a043563024b13b33d74a2b95b767c5f81bde8456e9d0413a89"
        },
        {
          "bytes": 614,
          "path": "bkupInfo.xml",
          "sha256": "a401a013543ca42ce2de0bd83d385f7eea1c097d84c1619e48aa43566ca31d30"
        },
        {
          "bytes": 262480,
          "path": "gpreport.xml",
          "sha256": "195e15693f5a49c7892593ab93c010b34373819b3574c949ba0f8375e1ec3225"
        }
      ],
      "name": "MSFT Windows Server 2025 v2602 - Domain Controller",
      "purpose": "MSFTWindowsServer2025v2602DomainController",
      "scope": "machine",
      "source_backup_path": "Windows Server 2025 Security Baseline - 2602/GPOs/{88603F56-DC8F-4132-8A8C-8FE5EB0B4B1A}",
      "source_display_name": "MSFT Windows Server 2025 v2602 - Domain Controller",
      "source_gpo_id": "{282955A8-792D-4CBA-A7C2-2A7CF863CF72}",
      "source_options": 1,
      "source_package_name": "Windows Server 2025 Security Baseline - 2602.zip",
      "source_package_sha256": "a66dffbe2622c3c4dd70e44a7f2080f362fb2d6f9208c50678671cbb046a286f",
      "source_package_url": "https://download.microsoft.com/download/e99be2d2-e077-4986-a06b-6078051999dd/Windows%20Server%202025%20Security%20Baseline%20-%202602.zip"
    },
    {
      "artifact_filename": "c4b6aeb7ae9c857eec76ef6c22d07fabc90135672a76836c1c6623ee17b68a43.ipmsgpo",
      "artifact_sha256": "c4b6aeb7ae9c857eec76ef6c22d07fabc90135672a76836c1c6623ee17b68a43",
      "artifact_size": 76201,
      "backup_id": "{B0CBE378-B19F-440E-A939-80B79E48C4EF}",
      "baseline_id": "microsoft-windows-server-2025",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 3626,
          "path": "Backup.xml",
          "sha256": "6b7c75446da9f3601ec02deb413da3d4a96b1eb2b2c79aed904230bfaf043e4f"
        },
        {
          "bytes": 554,
          "path": "DomainSysvol/GPO/Machine/comment.cmtx",
          "sha256": "f4cb5d64e7a8cec20da34b276020efb31262ab81bc325d754578d60f87d5e387"
        },
        {
          "bytes": 5698,
          "path": "DomainSysvol/GPO/Machine/registry.pol",
          "sha256": "d7353b2f77536c902aac53977aac412b68229ed97a84c422eac95e5aca3a168d"
        },
        {
          "bytes": 615,
          "path": "bkupInfo.xml",
          "sha256": "c40c4fd84316d0e57415219e33496468835df32f9c2bf1124b1f85fc999f9edb"
        },
        {
          "bytes": 65676,
          "path": "gpreport.xml",
          "sha256": "b81332510e6ac5b17befce621d104a56cccac4e74ab2c06ca88b87212201218d"
        }
      ],
      "name": "MSFT Windows Server 2025 v2602 - Defender Antivirus",
      "purpose": "MSFTWindowsServer2025v2602DefenderAntivirus",
      "scope": "machine",
      "source_backup_path": "Windows Server 2025 Security Baseline - 2602/GPOs/{B0CBE378-B19F-440E-A939-80B79E48C4EF}",
      "source_display_name": "MSFT Windows Server 2025 v2602 - Defender Antivirus",
      "source_gpo_id": "{AB7F5E75-2737-4AA3-B1C2-33E7CE062DA8}",
      "source_options": 1,
      "source_package_name": "Windows Server 2025 Security Baseline - 2602.zip",
      "source_package_sha256": "a66dffbe2622c3c4dd70e44a7f2080f362fb2d6f9208c50678671cbb046a286f",
      "source_package_url": "https://download.microsoft.com/download/e99be2d2-e077-4986-a06b-6078051999dd/Windows%20Server%202025%20Security%20Baseline%20-%202602.zip"
    },
    {
      "artifact_filename": "4c97c9f3901e4125ad5d7b7144a368a6ad87622843ad4207f9784441db803676.ipmsgpo",
      "artifact_sha256": "4c97c9f3901e4125ad5d7b7144a368a6ad87622843ad4207f9784441db803676",
      "artifact_size": 40615,
      "backup_id": "{B637F7F1-09CA-46B8-AC6C-E47E7F2F0F41}",
      "baseline_id": "microsoft-windows-server-2025",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 3732,
          "path": "Backup.xml",
          "sha256": "4bec7250cc398970bb29d712ff131b708f361dde1993f68fe9981777d1d21c62"
        },
        {
          "bytes": 549,
          "path": "DomainSysvol/GPO/Machine/comment.cmtx",
          "sha256": "94f49ee096c38f34ddf86a3d864661da5a39cca6a641ce5db6c159bf106d8e01"
        },
        {
          "bytes": 1392,
          "path": "DomainSysvol/GPO/Machine/registry.pol",
          "sha256": "63db016aabd72726c333671ab7e8c6726e2a086477dc6a9082f0d6ab98dfb7ae"
        },
        {
          "bytes": 644,
          "path": "bkupInfo.xml",
          "sha256": "9c2303d6d3111668abf62d5258da364e7c62f75fdcbb310d72cadf80f0392e1a"
        },
        {
          "bytes": 34266,
          "path": "gpreport.xml",
          "sha256": "b6835876edc0a21edd16f75ec17ebf00b6355ef545ed216064645408d301984e"
        }
      ],
      "name": "MSFT Windows Server 2025 v2602 - Domain Controller Virtualization Based Security",
      "purpose": "MSFTWindowsServer2025v2602DomainControllerVirtualizationBasedSecurity",
      "scope": "machine",
      "source_backup_path": "Windows Server 2025 Security Baseline - 2602/GPOs/{B637F7F1-09CA-46B8-AC6C-E47E7F2F0F41}",
      "source_display_name": "MSFT Windows Server 2025 v2602 - Domain Controller Virtualization Based Security",
      "source_gpo_id": "{9B21A652-8DFD-492E-9F0C-C9FDC18FE13D}",
      "source_options": 1,
      "source_package_name": "Windows Server 2025 Security Baseline - 2602.zip",
      "source_package_sha256": "a66dffbe2622c3c4dd70e44a7f2080f362fb2d6f9208c50678671cbb046a286f",
      "source_package_url": "https://download.microsoft.com/download/e99be2d2-e077-4986-a06b-6078051999dd/Windows%20Server%202025%20Security%20Baseline%20-%202602.zip"
    },
    {
      "artifact_filename": "a4e65705256995711b173d9ae629215c4f71ac1128bef05ecd4c81d129fd63cc.ipmsgpo",
      "artifact_sha256": "a4e65705256995711b173d9ae629215c4f71ac1128bef05ecd4c81d129fd63cc",
      "artifact_size": 25128,
      "backup_id": "{F74D904A-2A4B-4865-8877-3E71FEFF91FF}",
      "baseline_id": "microsoft-windows-server-2025",
      "directories": [
        "DomainSysvol",
        "DomainSysvol/GPO",
        "DomainSysvol/GPO/Machine",
        "DomainSysvol/GPO/Machine/Applications",
        "DomainSysvol/GPO/Machine/microsoft",
        "DomainSysvol/GPO/Machine/microsoft/windows nt",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/Audit",
        "DomainSysvol/GPO/Machine/microsoft/windows nt/SecEdit",
        "DomainSysvol/GPO/User"
      ],
      "files": [
        {
          "bytes": 5069,
          "path": "Backup.xml",
          "sha256": "7ed7aaeb86a374475dd3fa72bf8ddb8801bcb01419fd2550b4189d2ff249c852"
        },
        {
          "bytes": 901,
          "path": "DomainSysvol/GPO/User/comment.cmtx",
          "sha256": "4626e59f12f72f994ce0a1591e5fbcfb1c83cc60462c35d3dff42f745cb0ea30"
        },
        {
          "bytes": 534,
          "path": "DomainSysvol/GPO/User/registry.pol",
          "sha256": "bdc7178487ef6346e2e4796ac6aae54a2076f950cb541bb4bd88c7c4a6874a96"
        },
        {
          "bytes": 596,
          "path": "bkupInfo.xml",
          "sha256": "acd4a67b757a8bc980c8e77612d16dfdd46fb933d7817a0a19e5e78118e2eff9"
        },
        {
          "bytes": 17996,
          "path": "gpreport.xml",
          "sha256": "366c515e56d28bfe3968ad1c427dbc52e4cfe86ff94eed7f3ca3d1b10a2e02c5"
        }
      ],
      "name": "MSFT Internet Explorer 11 - User",
      "purpose": "MSFTInternetExplorer11User",
      "scope": "user",
      "source_backup_path": "Windows Server 2025 Security Baseline - 2602/GPOs/{F74D904A-2A4B-4865-8877-3E71FEFF91FF}",
      "source_display_name": "MSFT Internet Explorer 11 - User",
      "source_gpo_id": "{582D31BD-8974-43C8-B88B-FC18B4254E87}",
      "source_options": 2,
      "source_package_name": "Windows Server 2025 Security Baseline - 2602.zip",
      "source_package_sha256": "a66dffbe2622c3c4dd70e44a7f2080f362fb2d6f9208c50678671cbb046a286f",
      "source_package_url": "https://download.microsoft.com/download/e99be2d2-e077-4986-a06b-6078051999dd/Windows%20Server%202025%20Security%20Baseline%20-%202602.zip"
    }
  ],
  "format": "IPMSGPO1",
  "profiles": [
    {
      "backup_ids": [
        "{202BE0F1-CE9C-4435-BF43-56E18F5BF7D3}",
        "{8C841835-DE87-46E6-98A2-B59B959BFD59}",
        "{CB79185B-5015-497C-8F1E-48E9E3B4ABB6}",
        "{AA94F467-FC14-4789-A1C4-7F74B23184B2}",
        "{BA48C326-B51D-47B1-8CED-547FC046DCA7}",
        "{522ED121-0E11-41F6-A205-CC736B4DEE1E}",
        "{816D1B8C-378B-48D9-B2F4-D5E582A57D7C}",
        "{C91CAC2A-3421-404F-A1B6-025301CE3261}"
      ],
      "baseline_id": "microsoft-windows-10-22h2",
      "profile": "client"
    },
    {
      "backup_ids": [
        "{72D4230C-5BFB-497D-BC14-67F7E18F2954}",
        "{A59C7553-3449-43AD-929F-368ABC4B3EDF}",
        "{39B711D6-ACD3-42D7-BA55-47CBD4D3B1C7}",
        "{9E9FAF7E-9ED1-4B19-8F5F-65A37ACD39AF}",
        "{A484ECC9-232E-44F0-BEF6-05BC7231727A}",
        "{D0E7DD4A-C681-488D-995A-0F061575BCE3}",
        "{A4EA0481-872A-4286-839D-A64FFC8F521B}",
        "{7AFCEE57-FD46-4225-94E7-A80DD57D1A31}"
      ],
      "baseline_id": "microsoft-windows-11-23h2",
      "profile": "client"
    },
    {
      "backup_ids": [
        "{BB10D67B-FBEA-4CD0-8E5F-09AC67C07670}",
        "{BF76B495-48DD-4A15-AFFF-E9E20A6C9AAB}",
        "{9DD51389-33D0-4D19-8274-F9C19C54AACB}",
        "{DAD42DA1-8499-42FE-A1CD-9E39196D8B98}",
        "{3C4158A9-6823-4577-8AAE-197181A6E6AD}",
        "{DD32F334-CB07-4579-96E3-06F27B6B5FAB}",
        "{04602802-38C4-4900-87CD-B126DA8875ED}",
        "{C4FCE0A9-BC29-4589-A63D-144E8CD991CE}"
      ],
      "baseline_id": "microsoft-windows-11-24h2",
      "profile": "client"
    },
    {
      "backup_ids": [
        "{1879C2DC-00C6-4692-B167-15B9366DF5D4}",
        "{56977988-BEEC-4E61-B649-731EC7AB997B}",
        "{E2D5B48E-8BB0-4ACC-AEB6-8DD82FDD825F}",
        "{02DB0E53-0925-4E5A-B775-E7A1A9370AB8}",
        "{FC357767-040F-49C3-965E-B071D17C29A0}",
        "{D42CD0A5-F321-4CB1-ADA9-03A0F0A6E3B2}",
        "{666ED8AB-DF4A-45CE-9666-61F802515051}",
        "{D233D0A9-D74E-4AEE-9B89-2398C7AD1DDE}"
      ],
      "baseline_id": "microsoft-windows-11-25h2",
      "profile": "client"
    },
    {
      "backup_ids": [
        "{37BBB33A-A159-427D-AD58-67B1BE126AD6}",
        "{4095647A-14FE-4CE4-955A-F2311B0D62D1}",
        "{714FD77E-8FDD-4CB0-B3F7-FF49815473FF}",
        "{1D2C9D38-6BB1-4C90-B5EB-2850EA18AE06}"
      ],
      "baseline_id": "microsoft-windows-server-2016",
      "profile": "domain-controller"
    },
    {
      "backup_ids": [
        "{088E04EC-440C-48CB-A8D7-A89D0162FBFB}",
        "{9C87270F-7704-41D9-A76D-C8B9ADB1794A}",
        "{07177AF8-97DF-407D-89A6-C875CD1784BC}",
        "{B0AA555D-B555-4832-9BA6-2D5A973A7B92}",
        "{4095647A-14FE-4CE4-955A-F2311B0D62D1}",
        "{714FD77E-8FDD-4CB0-B3F7-FF49815473FF}",
        "{1D2C9D38-6BB1-4C90-B5EB-2850EA18AE06}"
      ],
      "baseline_id": "microsoft-windows-server-2016",
      "profile": "server"
    },
    {
      "backup_ids": [
        "{ABFB52F2-1560-4100-9103-8C10F57DC9DE}",
        "{E913422C-4F06-4D37-A739-2CD2B701978E}",
        "{FEE76283-957E-4B25-9380-2F737E13E972}",
        "{B9263530-926F-46F3-8382-832C31EC81B5}",
        "{FEFBD334-CF33-4078-8829-4B00DC1D164B}",
        "{7EA149BF-56B3-42CF-AF68-3FC789510ADD}"
      ],
      "baseline_id": "microsoft-windows-server-2019",
      "profile": "domain-controller"
    },
    {
      "backup_ids": [
        "{ABFB52F2-1560-4100-9103-8C10F57DC9DE}",
        "{E913422C-4F06-4D37-A739-2CD2B701978E}",
        "{FEE76283-957E-4B25-9380-2F737E13E972}",
        "{B9263530-926F-46F3-8382-832C31EC81B5}",
        "{7D41EEC9-3F30-4473-9447-E77D6EEF0E17}",
        "{C92CC433-A4EA-47B1-8B24-6FF732940E0E}"
      ],
      "baseline_id": "microsoft-windows-server-2019",
      "profile": "server"
    },
    {
      "backup_ids": [
        "{0A531EAC-7B92-4E02-9877-1FB7CBE41398}",
        "{BEA08B79-482E-4216-B5DE-8528F3688DD5}",
        "{966B53AB-4B25-43F6-BACA-9738F0053331}",
        "{E2B8214C-729F-4324-A876-F067E58B740B}",
        "{8104AFEB-D49C-4125-92F9-748F50407A6B}",
        "{AAC7C960-51D3-4BEE-89BD-7FB10361AA16}"
      ],
      "baseline_id": "microsoft-windows-server-2022",
      "profile": "domain-controller"
    },
    {
      "backup_ids": [
        "{0A531EAC-7B92-4E02-9877-1FB7CBE41398}",
        "{BEA08B79-482E-4216-B5DE-8528F3688DD5}",
        "{966B53AB-4B25-43F6-BACA-9738F0053331}",
        "{AAC7C960-51D3-4BEE-89BD-7FB10361AA16}",
        "{20FAD6FB-7C6D-496E-801C-0434769847FF}",
        "{64059F15-E999-4E2F-865D-C0766B886266}"
      ],
      "baseline_id": "microsoft-windows-server-2022",
      "profile": "server"
    },
    {
      "backup_ids": [
        "{2E1948EE-56EE-45A1-9473-D5A4C2153E5F}",
        "{F74D904A-2A4B-4865-8877-3E71FEFF91FF}",
        "{B0CBE378-B19F-440E-A939-80B79E48C4EF}",
        "{88603F56-DC8F-4132-8A8C-8FE5EB0B4B1A}",
        "{B637F7F1-09CA-46B8-AC6C-E47E7F2F0F41}",
        "{40CF40AD-F1B2-433F-A5C9-032DB7424608}"
      ],
      "baseline_id": "microsoft-windows-server-2025",
      "profile": "domain-controller"
    },
    {
      "backup_ids": [
        "{2E1948EE-56EE-45A1-9473-D5A4C2153E5F}",
        "{F74D904A-2A4B-4865-8877-3E71FEFF91FF}",
        "{B0CBE378-B19F-440E-A939-80B79E48C4EF}",
        "{40CF40AD-F1B2-433F-A5C9-032DB7424608}",
        "{066B7FF5-BF2B-4B1B-8A92-2A83B8619444}",
        "{5DCDD718-EB35-4D88-9E9A-2B936D7B8A4B}"
      ],
      "baseline_id": "microsoft-windows-server-2025",
      "profile": "server"
    }
  ],
  "schema_version": 1
}
''')
if hashlib.sha256(json.dumps(_CATALOG, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')).hexdigest() != CATALOG_SHA256:
    raise RuntimeError('GPO backup catalog integrity check failed')
COMPONENTS = {(item['baseline_id'], item['backup_id']): item for item in _CATALOG['components']}
PROFILE_COMPONENTS = {(item['baseline_id'], item['profile']): tuple(item['backup_ids']) for item in _CATALOG['profiles']}

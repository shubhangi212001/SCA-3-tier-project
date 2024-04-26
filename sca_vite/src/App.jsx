import React, { Component, useState } from "react";
import { render } from "react-dom";
// import reactLogo from './assets/esds-sca.svg'
// import viteLogo from '/vite.svg'
import axios from "axios";
// import SyntaxHighlighter from 'react-syntax-highlighter';
// import { docco } from 'react-syntax-highlighter/dist/esm/styles/hljs';
import "./App.css";
import Loading from "./common/Loading";
import {
  Button,
  Box,
  Grid,
  TextField,
  Card,
  CardHeader,
  Typography,
  Divider,
  Link,
  InputLabel,
  Select,
  FormControl,
  MenuItem,
} from "@mui/material";
import UploadFileIcon from "@mui/icons-material/UploadFile";
import FileDownloadIcon from "@mui/icons-material/FileDownload";
import { PDFExport, savePDF } from "@progress/kendo-react-pdf";

import Accordion from "@mui/material/Accordion";
import AccordionSummary from "@mui/material/AccordionSummary";
import AccordionDetails from "@mui/material/AccordionDetails";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";

const App = () => {
  const [filename, setFilename] = useState("");
  const [file, setFile] = useState("");
  const [language, setLanguage] = useState("");
  const [vulnerability, setVulnerability] = useState("");
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(false);
  const [downloadBtnVisible, setDownloadBtnVisible] = useState("none");
  
  const productData = [
    {
      total_cve: 19,
    },
    {
      cve_id: "CVE-2021-31542",
      vulnerability:
        "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
      description:
        "In Django 2.2 before 2.2.21, 3.1 before 3.1.9, and 3.2 before 3.2.1, MultiPartParser, UploadedFile, and FieldFile allowed directory traversal via uploaded files with suitably crafted file names.",
      product_name: "django",
      problemtype: "CWE-22",
      configurations: [
        {
          versionEndExcluding: "2.2.21",
        },
        {
          versionEndExcluding: "3.1.9",
        },
        {
          versionEndExcluding: "3.2.1",
        },
      ],
      references: [
        "http://www.openwall.com/lists/oss-security/2021/05/04/3",
        "https://docs.djangoproject.com/en/3.2/releases/security/",
        "https://groups.google.com/forum/#!forum/django-announce",
        "https://lists.debian.org/debian-lts-announce/2021/05/msg00005.html",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/B4SQG2EAF4WCI2SLRL6XRDJ3RPK3ZRDV/",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZVKYPHR3TKR2ESWXBPOJEKRO2OSJRZUE/",
        "https://security.netapp.com/advisory/ntap-20210618-0001/",
        "https://www.djangoproject.com/weblog/2021/may/04/security-releases/",
      ],
      impact: {
        base_score: 7.5,
        base_severity: "HIGH",
      },
    },
    {
      cve_id: "CVE-2021-32052",
      vulnerability:
        "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
      description:
        "In Django 2.2 before 2.2.22, 3.1 before 3.1.10, and 3.2 before 3.2.2 (with Python 3.9.5+), URLValidator does not prohibit newlines and tabs (unless the URLField form field is used). If an application uses values with newlines in an HTTP response, header injection can occur. Django itself is unaffected because HttpResponse prohibits newlines in HTTP headers.",
      product_name: "django",
      problemtype: "CWE-79",
      configurations: [
        {
          versionEndExcluding: "2.2.22",
        },
        {
          versionEndExcluding: "3.1.10",
        },
        {
          versionEndExcluding: "3.2.2",
        },
        {},
      ],
      references: [
        "http://www.openwall.com/lists/oss-security/2021/05/06/1",
        "https://docs.djangoproject.com/en/3.2/releases/security/",
        "https://groups.google.com/forum/#!forum/django-announce",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZVKYPHR3TKR2ESWXBPOJEKRO2OSJRZUE/",
        "https://security.netapp.com/advisory/ntap-20210611-0002/",
        "https://www.djangoproject.com/weblog/2021/may/06/security-releases/",
      ],
      impact: {
        base_score: 6.1,
        base_severity: "MEDIUM",
      },
    },
    {
      cve_id: "CVE-2021-33571",
      vulnerability: "Server-Side Request Forgery (SSRF)",
      description:
        "In Django 2.2 before 2.2.24, 3.x before 3.1.12, and 3.2 before 3.2.4, URLValidator, validate_ipv4_address, and validate_ipv46_address do not prohibit leading zero characters in octal literals. This may allow a bypass of access control that is based on IP addresses. (validate_ipv4_address and validate_ipv46_address are unaffected with Python 3.9.5+..) .",
      product_name: "django",
      problemtype: "CWE-918",
      configurations: [
        {
          versionEndExcluding: "2.2.24",
        },
        {
          versionEndExcluding: "3.1.12",
        },
        {
          versionEndExcluding: "3.2.4",
        },
      ],
      references: [
        "https://docs.djangoproject.com/en/3.2/releases/security/",
        "https://groups.google.com/g/django-announce/c/sPyjSKMi8Eo",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/B4SQG2EAF4WCI2SLRL6XRDJ3RPK3ZRDV/",
        "https://security.netapp.com/advisory/ntap-20210727-0004/",
        "https://www.djangoproject.com/weblog/2021/jun/02/security-releases/",
      ],
      impact: {
        base_score: 7.5,
        base_severity: "HIGH",
      },
    },
    {
      cve_id: "CVE-2021-35042",
      vulnerability:
        "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
      description:
        "Django 3.1.x before 3.1.13 and 3.2.x before 3.2.5 allows QuerySet.order_by SQL injection if order_by is untrusted input from a client of a web application.",
      product_name: "django",
      problemtype: "CWE-89",
      configurations: [
        {
          versionEndExcluding: "3.1.13",
        },
        {
          versionEndExcluding: "3.2.5",
        },
      ],
      references: [
        "https://docs.djangoproject.com/en/3.2/releases/security/",
        "https://groups.google.com/forum/#!forum/django-announce",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/SS6NJTBYWOX6J7G4U3LUOILARJKWPQ5Y/",
        "https://security.netapp.com/advisory/ntap-20210805-0008/",
        "https://www.djangoproject.com/weblog/2021/jul/01/security-releases/",
        "https://www.openwall.com/lists/oss-security/2021/07/02/2",
      ],
      impact: {
        base_score: 9.8,
        base_severity: "CRITICAL",
      },
    },
    {
      cve_id: "CVE-2021-44420",
      vulnerability: "None",
      description:
        "In Django 2.2 before 2.2.25, 3.1 before 3.1.14, and 3.2 before 3.2.10, HTTP requests for URLs with trailing newlines could bypass upstream access control based on URL paths.",
      product_name: "django",
      problemtype: "NVD-CWE-Other",
      configurations: [
        {
          versionEndExcluding: "2.2.25",
        },
        {
          versionEndExcluding: "3.1.14",
        },
        {
          versionEndExcluding: "3.2.10",
        },
      ],
      references: [
        "https://docs.djangoproject.com/en/3.2/releases/security/",
        "https://groups.google.com/forum/#!forum/django-announce",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/B4SQG2EAF4WCI2SLRL6XRDJ3RPK3ZRDV/",
        "https://security.netapp.com/advisory/ntap-20211229-0006/",
        "https://www.djangoproject.com/weblog/2021/dec/07/security-releases/",
        "https://www.openwall.com/lists/oss-security/2021/12/07/1",
      ],
      impact: {
        base_score: 7.3,
        base_severity: "HIGH",
      },
    },
    {
      cve_id: "CVE-2021-45115",
      vulnerability: "None",
      description:
        "An issue was discovered in Django 2.2 before 2.2.26, 3.2 before 3.2.11, and 4.0 before 4.0.1. UserAttributeSimilarityValidator incurred significant overhead in evaluating a submitted password that was artificially large in relation to the comparison values. In a situation where access to user registration was unrestricted, this provided a potential vector for a denial-of-service attack.",
      product_name: "django",
      problemtype: "NVD-CWE-Other",
      configurations: [
        {
          versionEndExcluding: "2.2.26",
        },
        {
          versionEndExcluding: "3.2.11",
        },
        {
          versionEndExcluding: "4.0.1",
        },
      ],
      references: [
        "https://docs.djangoproject.com/en/4.0/releases/security/",
        "https://groups.google.com/forum/#!forum/django-announce",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/B4SQG2EAF4WCI2SLRL6XRDJ3RPK3ZRDV/",
        "https://security.netapp.com/advisory/ntap-20220121-0005/",
        "https://www.djangoproject.com/weblog/2022/jan/04/security-releases/",
      ],
      impact: {
        base_score: 7.5,
        base_severity: "HIGH",
      },
    },
    {
      cve_id: "CVE-2021-45116",
      vulnerability: "Improper Input Validation",
      description:
        "An issue was discovered in Django 2.2 before 2.2.26, 3.2 before 3.2.11, and 4.0 before 4.0.1. Due to leveraging the Django Template Language's variable resolution logic, the dictsort template filter was potentially vulnerable to information disclosure, or an unintended method call, if passed a suitably crafted key.",
      product_name: "django",
      problemtype: "CWE-20",
      configurations: [
        {
          versionEndExcluding: "2.2.26",
        },
        {
          versionEndExcluding: "3.2.11",
        },
        {
          versionEndExcluding: "4.0.1",
        },
      ],
      references: [
        "https://docs.djangoproject.com/en/4.0/releases/security/",
        "https://groups.google.com/forum/#!forum/django-announce",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/B4SQG2EAF4WCI2SLRL6XRDJ3RPK3ZRDV/",
        "https://security.netapp.com/advisory/ntap-20220121-0005/",
        "https://www.djangoproject.com/weblog/2022/jan/04/security-releases/",
      ],
      impact: {
        base_score: 7.5,
        base_severity: "HIGH",
      },
    },
    {
      cve_id: "CVE-2021-45452",
      vulnerability:
        "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
      description:
        "Storage.save in Django 2.2 before 2.2.26, 3.2 before 3.2.11, and 4.0 before 4.0.1 allows directory traversal if crafted filenames are directly passed to it.",
      product_name: "django",
      problemtype: "CWE-22",
      configurations: [
        {
          versionEndExcluding: "2.2.26",
        },
        {
          versionEndExcluding: "3.2.11",
        },
        {
          versionEndExcluding: "4.0.1",
        },
      ],
      references: [
        "https://docs.djangoproject.com/en/4.0/releases/security/",
        "https://groups.google.com/forum/#!forum/django-announce",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/B4SQG2EAF4WCI2SLRL6XRDJ3RPK3ZRDV/",
        "https://security.netapp.com/advisory/ntap-20220121-0005/",
        "https://www.djangoproject.com/weblog/2022/jan/04/security-releases/",
      ],
      impact: {
        base_score: 5.3,
        base_severity: "MEDIUM",
      },
    },
    {
      cve_id: "CVE-2022-22818",
      vulnerability:
        "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
      description:
        "The {% debug %} template tag in Django 2.2 before 2.2.27, 3.2 before 3.2.12, and 4.0 before 4.0.2 does not properly encode the current context. This may lead to XSS.",
      product_name: "django",
      problemtype: "CWE-79",
      configurations: [
        {
          versionEndExcluding: "2.2.27",
        },
        {
          versionEndExcluding: "3.2.12",
        },
        {
          versionEndExcluding: "4.0.2",
        },
      ],
      references: [
        "https://docs.djangoproject.com/en/4.0/releases/security/",
        "https://groups.google.com/forum/#!forum/django-announce",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/B4SQG2EAF4WCI2SLRL6XRDJ3RPK3ZRDV/",
        "https://security.netapp.com/advisory/ntap-20220221-0003/",
        "https://www.debian.org/security/2022/dsa-5254",
        "https://www.djangoproject.com/weblog/2022/feb/01/security-releases/",
      ],
      impact: {
        base_score: 6.1,
        base_severity: "MEDIUM",
      },
    },
    {
      cve_id: "CVE-2022-23833",
      vulnerability: "Loop with Unreachable Exit Condition ('Infinite Loop')",
      description:
        "An issue was discovered in MultiPartParser in Django 2.2 before 2.2.27, 3.2 before 3.2.12, and 4.0 before 4.0.2. Passing certain inputs to multipart forms could result in an infinite loop when parsing files.",
      product_name: "django",
      problemtype: "CWE-835",
      configurations: [
        {
          versionEndExcluding: "2.2.27",
        },
        {
          versionEndExcluding: "3.2.12",
        },
        {
          versionEndExcluding: "4.0.2",
        },
      ],
      references: [
        "https://docs.djangoproject.com/en/4.0/releases/security/",
        "https://groups.google.com/forum/#!forum/django-announce",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/B4SQG2EAF4WCI2SLRL6XRDJ3RPK3ZRDV/",
        "https://security.netapp.com/advisory/ntap-20220221-0003/",
        "https://www.debian.org/security/2022/dsa-5254",
        "https://www.djangoproject.com/weblog/2022/feb/01/security-releases/",
      ],
      impact: {
        base_score: 7.5,
        base_severity: "HIGH",
      },
    },
    {
      cve_id: "CVE-2022-28346",
      vulnerability:
        "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
      description:
        "An issue was discovered in Django 2.2 before 2.2.28, 3.2 before 3.2.13, and 4.0 before 4.0.4. QuerySet.annotate(), aggregate(), and extra() methods are subject to SQL injection in column aliases via a crafted dictionary (with dictionary expansion) as the passed **kwargs.",
      product_name: "django",
      problemtype: "CWE-89",
      configurations: [
        {
          versionEndExcluding: "2.2.28",
        },
        {
          versionEndExcluding: "3.2.13",
        },
        {
          versionEndExcluding: "4.0.4",
        },
      ],
      references: [
        "http://www.openwall.com/lists/oss-security/2022/04/11/1",
        "https://docs.djangoproject.com/en/4.0/releases/security/",
        "https://groups.google.com/forum/#!forum/django-announce",
        "https://lists.debian.org/debian-lts-announce/2022/04/msg00013.html",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/HWY6DQWRVBALV73BPUVBXC3QIYUM24IK/",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/LTZVAKU5ALQWOKFTPISE257VCVIYGFQI/",
        "https://security.netapp.com/advisory/ntap-20220609-0002/",
        "https://www.debian.org/security/2022/dsa-5254",
        "https://www.djangoproject.com/weblog/2022/apr/11/security-releases/",
      ],
      impact: {
        base_score: 9.8,
        base_severity: "CRITICAL",
      },
    },
    {
      cve_id: "CVE-2022-28347",
      vulnerability:
        "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
      description:
        "A SQL injection issue was discovered in QuerySet.explain() in Django 2.2 before 2.2.28, 3.2 before 3.2.13, and 4.0 before 4.0.4. This occurs by passing a crafted dictionary (with dictionary expansion) as the **options argument, and placing the injection payload in an option name.",
      product_name: "django",
      problemtype: "CWE-89",
      configurations: [
        {
          versionEndExcluding: "2.2.28",
        },
        {
          versionEndExcluding: "3.2.13",
        },
        {
          versionEndExcluding: "4.0.4",
        },
      ],
      references: [
        "http://www.openwall.com/lists/oss-security/2022/04/11/1",
        "https://docs.djangoproject.com/en/4.0/releases/security/",
        "https://groups.google.com/forum/#!forum/django-announce",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/HWY6DQWRVBALV73BPUVBXC3QIYUM24IK/",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/LTZVAKU5ALQWOKFTPISE257VCVIYGFQI/",
        "https://www.debian.org/security/2022/dsa-5254",
        "https://www.djangoproject.com/weblog/2022/apr/11/security-releases/",
      ],
      impact: {
        base_score: 9.8,
        base_severity: "CRITICAL",
      },
    },
    {
      cve_id: "CVE-2022-34265",
      vulnerability:
        "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
      description:
        "An issue was discovered in Django 3.2 before 3.2.14 and 4.0 before 4.0.6. The Trunc() and Extract() database functions are subject to SQL injection if untrusted data is used as a kind/lookup_name value. Applications that constrain the lookup name and kind choice to a known safe list are unaffected.",
      product_name: "django",
      problemtype: "CWE-89",
      configurations: [
        {
          versionEndExcluding: "3.2.14",
        },
        {
          versionEndExcluding: "4.0.6",
        },
      ],
      references: [
        "https://docs.djangoproject.com/en/4.0/releases/security/",
        "https://groups.google.com/forum/#!forum/django-announce",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/HWY6DQWRVBALV73BPUVBXC3QIYUM24IK/",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/LTZVAKU5ALQWOKFTPISE257VCVIYGFQI/",
        "https://security.netapp.com/advisory/ntap-20220818-0006/",
        "https://www.debian.org/security/2022/dsa-5254",
        "https://www.djangoproject.com/weblog/2022/jul/04/security-releases/",
      ],
      impact: {
        base_score: 9.8,
        base_severity: "CRITICAL",
      },
    },
    {
      cve_id: "CVE-2022-36359",
      vulnerability: "Download of Code Without Integrity Check",
      description:
        "An issue was discovered in the HTTP FileResponse class in Django 3.2 before 3.2.15 and 4.0 before 4.0.7. An application is vulnerable to a reflected file download (RFD) attack that sets the Content-Disposition header of a FileResponse when the filename is derived from user-supplied input.",
      product_name: "django",
      problemtype: "CWE-494",
      configurations: [
        {
          versionEndExcluding: "3.2.15",
        },
        {
          versionEndExcluding: "4.0.7",
        },
      ],
      references: [
        "http://www.openwall.com/lists/oss-security/2022/08/03/1",
        "https://docs.djangoproject.com/en/4.0/releases/security/",
        "https://groups.google.com/g/django-announce/c/8cz--gvaJr4",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/HWY6DQWRVBALV73BPUVBXC3QIYUM24IK/",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/LTZVAKU5ALQWOKFTPISE257VCVIYGFQI/",
        "https://security.netapp.com/advisory/ntap-20220915-0008/",
        "https://www.debian.org/security/2022/dsa-5254",
        "https://www.djangoproject.com/weblog/2022/aug/03/security-releases/",
      ],
      impact: {
        base_score: 8.8,
        base_severity: "HIGH",
      },
    },
    {
      cve_id: "CVE-2022-41323",
      vulnerability: "None",
      description:
        "In Django 3.2 before 3.2.16, 4.0 before 4.0.8, and 4.1 before 4.1.2, internationalized URLs were subject to a potential denial of service attack via the locale parameter, which is treated as a regular expression.",
      product_name: "django",
      problemtype: "NVD-CWE-Other",
      configurations: [
        {
          versionEndExcluding: "3.2.16",
        },
        {
          versionEndExcluding: "4.0.8",
        },
        {
          versionEndExcluding: "4.1.2",
        },
      ],
      references: [
        "https://docs.djangoproject.com/en/4.0/releases/security/",
        "https://github.com/django/django/commit/5b6b257fa7ec37ff27965358800c67e2dd11c924",
        "https://groups.google.com/forum/#!forum/django-announce",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FKYVMMR7RPM6AHJ2SBVM2LO6D3NGFY7B/",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/HWY6DQWRVBALV73BPUVBXC3QIYUM24IK/",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/LTZVAKU5ALQWOKFTPISE257VCVIYGFQI/",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VZS4G6NSZWPTVXMMZHJOJVQEPL3QTO77/",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/YJB6FUBBLVKKG655UMTLQNN6UQ6EDLSP/",
        "https://security.netapp.com/advisory/ntap-20221124-0001/",
        "https://www.djangoproject.com/weblog/2022/oct/04/security-releases/",
      ],
      impact: {
        base_score: 7.5,
        base_severity: "HIGH",
      },
    },
    {
      cve_id: "CVE-2023-23969",
      vulnerability: "Allocation of Resources Without Limits or Throttling",
      description:
        "In Django 3.2 before 3.2.17, 4.0 before 4.0.9, and 4.1 before 4.1.6, the parsed values of Accept-Language headers are cached in order to avoid repetitive parsing. This leads to a potential denial-of-service vector via excessive memory usage if the raw value of Accept-Language headers is very large.",
      product_name: "django",
      problemtype: "CWE-770",
      configurations: [
        {
          versionEndExcluding: "3.2.17",
        },
        {
          versionEndExcluding: "4.0.9",
        },
        {
          versionEndExcluding: "4.1.6",
        },
      ],
      references: [
        "https://docs.djangoproject.com/en/4.1/releases/security/",
        "https://groups.google.com/forum/#!forum/django-announce",
        "https://lists.debian.org/debian-lts-announce/2023/02/msg00000.html",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/HWY6DQWRVBALV73BPUVBXC3QIYUM24IK/",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/LTZVAKU5ALQWOKFTPISE257VCVIYGFQI/",
        "https://security.netapp.com/advisory/ntap-20230302-0007/",
        "https://www.djangoproject.com/weblog/2023/feb/01/security-releases/",
      ],
      impact: {
        base_score: 7.5,
        base_severity: "HIGH",
      },
    },
    {
      cve_id: "CVE-2023-24580",
      vulnerability: "Uncontrolled Resource Consumption",
      description:
        "An issue was discovered in the Multipart Request Parser in Django 3.2 before 3.2.18, 4.0 before 4.0.10, and 4.1 before 4.1.7. Passing certain inputs (e.g., an excessive number of parts) to multipart forms could result in too many open files or memory exhaustion, and provided a potential vector for a denial-of-service attack.",
      product_name: "django",
      problemtype: "CWE-400",
      configurations: [
        {
          versionEndExcluding: "3.2.18",
        },
        {
          versionEndExcluding: "4.0.10",
        },
        {
          versionEndExcluding: "4.1.7",
        },
      ],
      references: [
        "http://www.openwall.com/lists/oss-security/2023/02/14/1",
        "https://docs.djangoproject.com/en/4.1/releases/security/",
        "https://groups.google.com/forum/#!forum/django-announce",
        "https://lists.debian.org/debian-lts-announce/2023/02/msg00023.html",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/FKYVMMR7RPM6AHJ2SBVM2LO6D3NGFY7B/",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/HWY6DQWRVBALV73BPUVBXC3QIYUM24IK/",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/LTZVAKU5ALQWOKFTPISE257VCVIYGFQI/",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/VZS4G6NSZWPTVXMMZHJOJVQEPL3QTO77/",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/YJB6FUBBLVKKG655UMTLQNN6UQ6EDLSP/",
        "https://security.netapp.com/advisory/ntap-20230316-0006/",
        "https://www.djangoproject.com/weblog/2023/feb/14/security-releases/",
      ],
      impact: {
        base_score: 7.5,
        base_severity: "HIGH",
      },
    },
    {
      cve_id: "CVE-2023-31047",
      vulnerability: "Improper Input Validation",
      description:
        'In Django 3.2 before 3.2.19, 4.x before 4.1.9, and 4.2 before 4.2.1, it was possible to bypass validation when using one form field to upload multiple files. This multiple upload has never been supported by forms.FileField or forms.ImageField (only the last uploaded file was validated). However, Django\'s "Uploading multiple files" documentation suggested otherwise.',
      product_name: "django",
      problemtype: "CWE-20",
      configurations: [
        {
          versionEndExcluding: "3.2.19",
        },
        {
          versionEndExcluding: "4.1.9",
        },
        {},
        {},
        {},
      ],
      references: [
        "https://docs.djangoproject.com/en/4.2/releases/security/",
        "https://groups.google.com/forum/#!forum/django-announce",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/A45VKTUVQ2BN6D5ZLZGCM774R6QGFOHW/",
        "https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/DNEHD6N435OE2XUFGDAAVAXSYWLCUBFD/",
        "https://security.netapp.com/advisory/ntap-20230609-0008/",
        "https://www.djangoproject.com/weblog/2023/may/03/security-releases/",
      ],
      impact: {
        base_score: 9.8,
        base_severity: "CRITICAL",
      },
    },
    {
      cve_id: "CVE-2023-36053",
      vulnerability: "Inefficient Regular Expression Complexity",
      description:
        "In Django 3.2 before 3.2.20, 4 before 4.1.10, and 4.2 before 4.2.3, EmailValidator and URLValidator are subject to a potential ReDoS (regular expression denial of service) attack via a very large number of domain name labels of emails and URLs.",
      product_name: "django",
      problemtype: "CWE-1333",
      configurations: [
        {
          versionEndExcluding: "3.2.20",
        },
        {
          versionEndExcluding: "4.1.10",
        },
        {
          versionEndExcluding: "4.2.3",
        },
      ],
      references: [
        "https://docs.djangoproject.com/en/4.2/releases/security/",
        "https://groups.google.com/forum/#!forum/django-announce",
        "https://lists.debian.org/debian-lts-announce/2023/07/msg00022.html",
        "https://www.debian.org/security/2023/dsa-5465",
        "https://www.djangoproject.com/weblog/2023/jul/03/security-releases/",
      ],
      impact: {
        base_score: 7.5,
        base_severity: "HIGH",
      },
    },
  ];

  const handleFileUpload = (e) => {
    if (!e.target.files) {
      return;
    }
    const fileData = e.target.files[0];
    setFile(e.target.files[0]);
    const { name } = fileData;
    setFilename(name);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    const formData = new FormData();
    formData.append("file", file);
    formData.append("Vulnerability", vulnerability);
    formData.append("Language", language);
      await axios({
          method: 'post',
          url: import.meta.env.VITE_API_URL,
          data: formData,
          config: { headers: { 'Content-Type': 'application/json' } }
      })
          .then(function (response) {
              //handle success
              setData(response.data);
          })
          .catch(function (response) {
              //handle error
          });
    // setData(productData);
    setLoading(false);
  };

  const pdfExportComponent = React.useRef(null);

  const exportPDFWithComponent = async () => {
    if (pdfExportComponent.current) {
      await setDownloadBtnVisible("flex");
      pdfExportComponent.current.save();
      await setDownloadBtnVisible("none");
    }
  };

  const [isExpanded, setIsExpanded] = useState(false);
  const [accordionIndex, setAccordionIndex] = useState("");

  const handleAccordionChange = (event, key) => {
    setIsExpanded(!isExpanded);
    setAccordionIndex(key);
  };

  const productRender = data.map((val, i) => {
    return (
      <Grid item xs={12} key={i}>
        {i != 0 && (
          <Card
            style={{ width: "980px", padding: "20px", marginBottom: "10px" }}
            className="medium_blog"
            key={i}
          >
            <CardHeader
              className="bg"
              justify="space-between"
              spacing={24}
              title={
                <>
                  <Typography style={{ fontSize: "1rem" }}>
                    Product Name: {val["product_name"]}
                  </Typography>
                  <Typography>Severity: </Typography>{" "}
                  <Box
                    sx={{ width: "120px", borderRadius: "5px" }}
                    className={
                      val["impact"]["base_severity"] === "HIGH"
                        ? "bg-box-high"
                        : val["impact"]["base_severity"] === "MEDIUM"
                        ? "bg-box-medium"
                        : val["impact"]["base_severity"] === "CRITICAL"
                        ? "bg-box-critical"
                        : "bg-box-low"
                    }
                  >
                    <Typography>{val["impact"]["base_severity"]}</Typography>
                  </Box>
                </>
              }
            ></CardHeader>
            <Typography variant="span">CVE ID: {val["cve_id"]}</Typography>
            <br />
            <Divider />
            <Typography variant="span">Description:</Typography>
            <br />
            <Typography variant="span">{val["description"]}</Typography>
            <br />
            <Divider />
            <Accordion onChange={(event) => handleAccordionChange(event, i)}>
              <AccordionSummary
                expandIcon={<ExpandMoreIcon />}
                aria-controls="panel1a-content"
                id="panel1a-header"
              >
                {accordionIndex === i && isExpanded === true ? (
                  <Typography>Concise Details</Typography>
                ) : (
                  <Typography>Comprehensive Details</Typography>
                )}
              </AccordionSummary>
              <AccordionDetails>
                <div>
                  <Typography variant="span">Vulnerability:</Typography>
                  <br />
                  <Typography variant="span">{val["vulnerability"]}</Typography>
                  <br />
                  <Divider />
                  <Typography variant="span">Reference URL: </Typography>
                  <br />
                  {val["references"].map((urlVal, index) => {
                    return (
                      <>
                        <Link variant="span" href={urlVal} key={index}>
                          {urlVal}
                        </Link>
                        <Typography>
                          <br />
                        </Typography>
                      </>
                    );
                  })}
                  {val["configurations"].map((configVal, key) => {
                    // var vs = Array.from(val["configurations"].values(), verVal => configVal["versionEndExcluding"]).join(", ");
                    // console.log(vs);
                    return (
                      <Typography variant="span" key={key}>
                        {" Fixed Version - " +
                          (configVal["versionEndExcluding"]
                            ? configVal["versionEndExcluding"]
                            : "NA") +
                          " Score - " +
                          val["impact"]["base_score"] +
                          " CWE ID - " +
                          val["problemtype"]}
                      </Typography>
                    );
                  })}
                </div>
              </AccordionDetails>
            </Accordion>
          </Card>
        )}
      </Grid>
    );
  });

  const totalCVERender = data.map((val, i) => {
    return (
      <Grid item xs={12} key={i}>
        {i == 0 && (
          <CardHeader
            className="bg"
            title={
              <>
                <Typography style={{ display: "flex", fontSize: "1rem" }}>
                  Total CVE count: {val["total_cve"]}
                </Typography>
                {val["total_cve"] != 0 && (
                  <Button
                    style={{
                      display: "flex",
                      float: "right",
                    }}
                    variant="contained"
                    onClick={exportPDFWithComponent}
                    endIcon={<FileDownloadIcon />}
                  >
                    Download PDF
                  </Button>
                )}
              </>
            }
          ></CardHeader>
        )}
      </Grid>
    );
  });

  const productRenderForDownload = data.map((val, i) => {
    return (
      <Grid item xs={12} key={i}>
        {i != 0 && (
          <Card
            style={{ width: "980px", padding: "20px", marginBottom: "10px" }}
            className="medium_blog"
            key={i}
          >
            <CardHeader
              className="bg"
              justify="space-between"
              spacing={24}
              title={
                <>
                  <Typography style={{ fontSize: "1rem" }}>
                    Product Name: {val["product_name"]}
                  </Typography>
                  <Typography>Severity: </Typography>{" "}
                  <Box
                    sx={{ width: "120px", borderRadius: "5px" }}
                    className={
                      val["impact"]["base_severity"] === "HIGH"
                        ? "bg-box-high"
                        : val["impact"]["base_severity"] === "MEDIUM"
                        ? "bg-box-medium"
                        : val["impact"]["base_severity"] === "CRITICAL"
                        ? "bg-box-critical"
                        : "bg-box-low"
                    }
                  >
                    <Typography>{val["impact"]["base_severity"]}</Typography>
                  </Box>
                </>
              }
            ></CardHeader>
            <Typography variant="span">CVE ID: {val["cve_id"]}</Typography>
            <br />
            <Divider />
            <Typography variant="span">Description:</Typography>
            <br />
            <Typography variant="span">{val["description"]}</Typography>
            <br />
            <Divider />
            <div>
              <Typography variant="span">Vulnerability:</Typography>
              <br />
              <Typography variant="span">{val["vulnerability"]}</Typography>
              <br />
              <Divider />
              <Typography variant="span">Reference URL: </Typography>
              <br />
              {val["references"].map((urlVal, index) => {
                return (
                  <>
                    <Link variant="span" href={urlVal} key={index}>
                      {urlVal}
                    </Link>
                    <Typography>
                      <br />
                    </Typography>
                  </>
                );
              })}
              {val["configurations"].map((configVal, key) => {
                return (
                  <Typography variant="span" key={key}>
                    {" Fixed Version - " +
                      (configVal["versionEndExcluding"]
                        ? configVal["versionEndExcluding"]
                        : "NA") +
                      " Score - " +
                      val["impact"]["base_score"] +
                      " CWE ID - " +
                      val["problemtype"]}
                  </Typography>
                );
              })}
            </div>
          </Card>
        )}
      </Grid>
    );
  });

  const totalCVERenderForDownload = data.map((val, i) => {
    return (
      <Grid item xs={12} key={i}>
        {i == 0 && (
          <div
            style={{
              justifyContent: "center",
              alignItems: "center",
            }}
          >
            <img
              crossOrigin="anonymous"
              src="/src/assets/esds-sca.svg"
              alt="SCA Logo"
              width="50"
              height="50"
            />
            <Typography variant="h6">
              Software Composition Analysis (SCA)
            </Typography>
            <CardHeader
              className="bg"
              title={
                <>
                  <Typography style={{ display: "flex", fontSize: "1rem" }}>
                    Total CVE count: {val["total_cve"]}
                  </Typography>
                </>
              }
            ></CardHeader>
          </div>
        )}
      </Grid>
    );
  });

  return (
    <>
      <div
        style={{
          display: "flex",
          justifyContent: "center",
          alignItems: "center",
        }}
      >
        <img
          src="/src/assets/esds-sca.svg"
          alt="SCA Logo"
          width="150"
          height="150"
        />
      </div>
      <Box
        justifyContent="center"
        style={{
          padding: "20px",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
        }}
        sx={{
          "& .MuiTextField-root": { m: 1, width: "100%" },
          "& .MuiFormControl-root": { m: 1, width: "100%" },
        }}
      >
        <Card style={{ width: "600px" }}>
          <Grid
            container
            rowSpacing={1.5}
            columnSpacing={2}
            justifyContent="center"
            alignItems="center"
            style={{ padding: "20px", width: "100%" }}
          >
            <CardHeader
              title={
                <Typography variant="h6">
                  Software Composition Analysis (SCA)
                </Typography>
              }
            ></CardHeader>
            <Grid item xs={12}>
              <FormControl fullWidth>
                <InputLabel id="language-label">Language</InputLabel>
                <Select
                  required
                  labelId="language-label"
                  id="Language"
                  variant="standard"
                  value={language}
                  label="Language"
                  onChange={(e) => setLanguage(e.target.value)}
                >
                  <MenuItem value="Python">Python</MenuItem>
                  <MenuItem value="Java">Java</MenuItem>
                  <MenuItem value="Node">Node</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} className="d-none">
              <TextField
                required
                type="text"
                variant="standard"
                label="Vulnerability"
                value={vulnerability}
                onChange={(e) => setVulnerability(e.target.value)}
              />
            </Grid>
            <Grid item xs={12} className="uploadFile-d-flex">
              <Button
                component="label"
                variant="outlined"
                startIcon={<UploadFileIcon />}
                sx={{ marginRight: "1rem" }}
              >
                Upload File
                <input
                  type="file"
                  // accept=".txt"
                  hidden
                  onChange={handleFileUpload}
                />
              </Button>
              <Box>{filename}</Box>
            </Grid>
            <Grid item xs={12}>
              <Button
                component="label"
                variant="outlined"
                sx={{ marginRight: "1rem" }}
                onClick={handleSubmit}
              >
                Submit
              </Button>
            </Grid>
          </Grid>
        </Card>
      </Box>
      {loading === false ? (
        <Box
          justifyContent="center"
          style={{
            padding: "20px",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            flexDirection: "column",
          }}
        >
          <div style={{ display: downloadBtnVisible }}>
            <PDFExport
              ref={pdfExportComponent}
              paperSize="A2"
              fileName="SCA Report.pdf"
            >
              {totalCVERenderForDownload}
              {productRenderForDownload}
            </PDFExport>
          </div>
          {totalCVERender}
          {productRender}
        </Box>
      ) : (
        <>{Loading("transacting Data...")}</>
      )}
    </>
  );
};

export default App;

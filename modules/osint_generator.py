import urllib.parse
from modules.security_utils import sanitize_domain

OSINT_CATEGORIES = [
    {
        "id": "public_files",
        "title": "1. Publicly Indexed Files",
        "icon": "bi-folder2-open",
        "badge_color": "info",
        "description": "Locate various publicly indexed documents, spreadsheets, slides, and text exports.",
        "queries": [
            {
                "name": "General Office Documents",
                "template": 'site:{domain} filetype:doc OR filetype:docx OR filetype:rtf',
                "explanation": "Identifies Microsoft Word and RTF documents indexed on domain subpaths.",
                "operators": ["site:", "filetype:"]
            },
            {
                "name": "Spreadsheets & Workbooks",
                "template": 'site:{domain} filetype:xls OR filetype:xlsx OR filetype:csv',
                "explanation": "Discovers publicly indexed Excel sheets and CSV datasets which may contain customer, financial, or inventory lists.",
                "operators": ["site:", "filetype:"]
            },
            {
                "name": "Presentations & Slide Decks",
                "template": 'site:{domain} filetype:ppt OR filetype:pptx OR filetype:key',
                "explanation": "Finds PowerPoint and Keynote slide decks containing roadmaps or architecture diagrams.",
                "operators": ["site:", "filetype:"]
            },
            {
                "name": "Text & Markdown Notes",
                "template": 'site:{domain} filetype:txt OR filetype:md OR filetype:rst',
                "explanation": "Scans for plain text files, release notes, or readmes accessible via web root.",
                "operators": ["site:", "filetype:"]
            },
            {
                "name": "OpenDocument Formats",
                "template": 'site:{domain} filetype:odt OR filetype:ods OR filetype:odp',
                "explanation": "Searches for open standard productivity documents indexed by search spiders.",
                "operators": ["site:", "filetype:"]
            }
        ]
    },
    {
        "id": "pdf_discovery",
        "title": "2. PDF and Document Discovery",
        "icon": "bi-file-earmark-pdf",
        "badge_color": "danger",
        "description": "Targeted queries to discover indexed PDF manuals, whitepapers, financial statements, and contracts.",
        "queries": [
            {
                "name": "All Indexed PDF Documents",
                "template": 'site:{domain} filetype:pdf',
                "explanation": "Comprehensive list of all indexed PDF files hosted on the domain.",
                "operators": ["site:", "filetype:"]
            },
            {
                "name": "Confidential / Internal PDF References",
                "template": 'site:{domain} filetype:pdf intext:"confidential" OR intext:"internal use only" OR intext:"strictly private"',
                "explanation": "Finds indexed documents containing confidentiality marks or disclaimers.",
                "operators": ["site:", "filetype:", "intext:"]
            },
            {
                "name": "Policy & Compliance PDFs",
                "template": 'site:{domain} filetype:pdf intitle:"policy" OR intitle:"compliance" OR intitle:"guidelines"',
                "explanation": "Discovers governance policies, regulatory compliance filings, and employee handbooks.",
                "operators": ["site:", "filetype:", "intitle:"]
            },
            {
                "name": "Financial & Audit Reports",
                "template": 'site:{domain} filetype:pdf intext:"financial statement" OR intext:"annual report" OR intext:"audit report"',
                "explanation": "Retrieves investor relations reports, balance sheets, and audit filings.",
                "operators": ["site:", "filetype:", "intext:"]
            },
            {
                "name": "Vendor & Customer Contracts",
                "template": 'site:{domain} filetype:pdf intext:"agreement" OR intext:"contract" OR intext:"statement of work"',
                "explanation": "Identifies sample, draft, or exposed contract templates and statements of work.",
                "operators": ["site:", "filetype:", "intext:"]
            }
        ]
    },
    {
        "id": "login_auth",
        "title": "3. Login and Authentication Pages",
        "icon": "bi-shield-lock",
        "badge_color": "warning",
        "description": "Enumerate exposed administrative entry points, employee portals, SSO endpoints, and authentication interfaces.",
        "queries": [
            {
                "name": "Standard Login Portals",
                "template": 'site:{domain} inurl:login OR inurl:signin OR inurl:auth',
                "explanation": "Discovers primary user, customer, and member authentication endpoints.",
                "operators": ["site:", "inurl:"]
            },
            {
                "name": "Administrative & Dashboard Access",
                "template": 'site:{domain} inurl:admin OR inurl:administrator OR inurl:cpanel OR inurl:dashboard',
                "explanation": "Finds back-office administration portals and administrative consoles.",
                "operators": ["site:", "inurl:"]
            },
            {
                "name": "Password Reset & Account Recovery",
                "template": 'site:{domain} inurl:forgot-password OR inurl:password-reset OR inurl:recover',
                "explanation": "Enumerates credential recovery mechanisms and reset token endpoints.",
                "operators": ["site:", "inurl:"]
            },
            {
                "name": "Single Sign-On (SSO) & OAuth Endpoints",
                "template": 'site:{domain} inurl:sso OR inurl:oauth OR inurl:saml OR inurl:idp',
                "explanation": "Identifies federated identity providers and identity gateway interfaces.",
                "operators": ["site:", "inurl:"]
            },
            {
                "name": "Intranet & Employee Portals",
                "template": 'site:{domain} inurl:portal OR inurl:staff OR inurl:intranet OR inurl:employee',
                "explanation": "Locates internal staff communication boards, webmail access, or HR portals.",
                "operators": ["site:", "inurl:"]
            }
        ]
    },
    {
        "id": "directory_listing",
        "title": "4. Publicly Indexed Directories",
        "icon": "bi-folder-symlink",
        "badge_color": "primary",
        "description": "Detect web servers with enabled directory browsing revealing filesystem structures.",
        "queries": [
            {
                "name": "Apache / Nginx Directory Listing",
                "template": 'site:{domain} intitle:"index of /"',
                "explanation": "Classic signature for web directories that have indexing enabled without an index.html file.",
                "operators": ["site:", "intitle:"]
            },
            {
                "name": "Parent Directory Traversal Links",
                "template": 'site:{domain} intitle:"index of" "parent directory"',
                "explanation": "Matches standard web server file listing navigation headers.",
                "operators": ["site:", "intitle:"]
            },
            {
                "name": "Indexed Uploads & Assets Folders",
                "template": 'site:{domain} intitle:"index of /" inurl:uploads OR inurl:files OR inurl:assets',
                "explanation": "Identifies user upload directories or media repositories left open to directory listing.",
                "operators": ["site:", "intitle:", "inurl:"]
            },
            {
                "name": "IIS Directory Browsing",
                "template": 'site:{domain} intitle:"directory listing" OR intext:"[to parent directory]"',
                "explanation": "Detects Microsoft IIS directory browsing interfaces.",
                "operators": ["site:", "intitle:", "intext:"]
            }
        ]
    },
    {
        "id": "subdomains",
        "title": "5. Subdomain Discovery",
        "icon": "bi-diagram-3",
        "badge_color": "cyan",
        "description": "Uncover staging, testing, development, and external service subdomains using exclusion operators.",
        "queries": [
            {
                "name": "Subdomains via www Exclusion",
                "template": 'site:*.{domain} -site:www.{domain}',
                "explanation": "Excludes the primary www host to reveal auxiliary, staging, or internal hostnames.",
                "operators": ["site:", "-site:"]
            },
            {
                "name": "Dev, Staging & Test Subdomains",
                "template": 'site:*.{domain} (inurl:dev OR inurl:stage OR inurl:test OR inurl:beta OR inurl:qa)',
                "explanation": "Targets non-production environments that may have reduced security controls.",
                "operators": ["site:", "inurl:"]
            },
            {
                "name": "API & Microservice Hosts",
                "template": 'site:*.{domain} (inurl:api OR inurl:v1 OR inurl:v2 OR inurl:graphql OR inurl:gateway)',
                "explanation": "Discovers exposed API routers, GraphQL endpoints, and backend connectors.",
                "operators": ["site:", "inurl:"]
            },
            {
                "name": "Mail, Remote & VPN Endpoints",
                "template": 'site:*.{domain} (inurl:mail OR inurl:webmail OR inurl:vpn OR inurl:remote OR inurl:citrix)',
                "explanation": "Locates perimeter remote access gateways, corporate VPNs, and mail hosts.",
                "operators": ["site:", "inurl:"]
            }
        ]
    },
    {
        "id": "config_files",
        "title": "6. Exposed Configuration References",
        "icon": "bi-gear-wide-connected",
        "badge_color": "warning",
        "description": "Locate potential environmental configurations, credentials schemas, and secrets.",
        "queries": [
            {
                "name": "Environment & Dotenv Files",
                "template": 'site:{domain} inurl:".env" OR inurl:"env.local" OR inurl:"docker-compose.yml"',
                "explanation": "Looks for indexed environment configuration files containing operational secrets.",
                "operators": ["site:", "inurl:"]
            },
            {
                "name": "Web & Server Config Files",
                "template": 'site:{domain} filetype:conf OR filetype:cnf OR filetype:config OR filetype:ini',
                "explanation": "Finds web server and database configuration manifests.",
                "operators": ["site:", "filetype:"]
            },
            {
                "name": "XML & Web.config Files",
                "template": 'site:{domain} filetype:xml inurl:config OR inurl:settings OR inurl:web.config',
                "explanation": "Identifies .NET web.config and application configuration XML files.",
                "operators": ["site:", "filetype:", "inurl:"]
            },
            {
                "name": "JSON Settings & Package Manifests",
                "template": 'site:{domain} filetype:json inurl:settings OR inurl:config OR inurl:package.json',
                "explanation": "Discovers JavaScript application dependencies, package manifests, and configuration dumps.",
                "operators": ["site:", "filetype:", "inurl:"]
            },
            {
                "name": "YAML Orchestration & CI/CD",
                "template": 'site:{domain} filetype:yaml OR filetype:yml inurl:pipeline OR inurl:ci OR inurl:action',
                "explanation": "Scans for continuous integration scripts and container manifests.",
                "operators": ["site:", "filetype:", "inurl:"]
            }
        ]
    },
    {
        "id": "error_logs",
        "title": "7. Error Messages and Debug Information",
        "icon": "bi-bug",
        "badge_color": "danger",
        "description": "Find stack traces, SQL error messages, debug consoles, and system crash dumps.",
        "queries": [
            {
                "name": "General Web Application Logs",
                "template": 'site:{domain} filetype:log inurl:error OR inurl:access OR inurl:debug',
                "explanation": "Detects web application log files published or accessible over HTTP.",
                "operators": ["site:", "filetype:", "inurl:"]
            },
            {
                "name": "SQL Syntax Error Messages",
                "template": 'site:{domain} intext:"syntax error in query" OR intext:"fatal error" OR intext:"ORA-00933" OR intext:"mysql_fetch_array"',
                "explanation": "Searches for indexed web pages that displayed unhandled database exceptions.",
                "operators": ["site:", "intext:"]
            },
            {
                "name": "PHP & Framework Diagnostics",
                "template": 'site:{domain} intext:"Stack Trace:" OR intext:"Traceback (most recent call last):" OR intext:"Fatal error: Uncaught"',
                "explanation": "Identifies exposed Python, PHP, or Java application stack traces.",
                "operators": ["site:", "intext:"]
            },
            {
                "name": "PHP Info Diagnostics Pages",
                "template": 'site:{domain} inurl:info.php OR inurl:phpinfo.php OR intitle:"phpinfo()"',
                "explanation": "Finds active PHP configuration audit scripts exposing PHP modules and system paths.",
                "operators": ["site:", "inurl:", "intitle:"]
            }
        ]
    },
    {
        "id": "contact_info",
        "title": "8. Public Contact Information",
        "icon": "bi-people",
        "badge_color": "info",
        "description": "Discover employee rosters, email addresses, phone directories, and organizational charts.",
        "queries": [
            {
                "name": "Domain Specific Email Addresses",
                "template": 'site:{domain} intext:"@{domain}"',
                "explanation": "Gathers public email addresses indexed within web page text.",
                "operators": ["site:", "intext:"]
            },
            {
                "name": "Leadership & Staff Directories",
                "template": 'site:{domain} inurl:team OR inurl:staff OR inurl:leadership OR inurl:directory',
                "explanation": "Finds leadership bios, personnel names, and internal organization structure.",
                "operators": ["site:", "inurl:"]
            },
            {
                "name": "Contact & Support Channels",
                "template": 'site:{domain} inurl:contact OR inurl:support OR inurl:helpdesk',
                "explanation": "Enumerates published support telephone numbers, mailing addresses, and desks.",
                "operators": ["site:", "inurl:"]
            },
            {
                "name": "Vulnerability Disclosure & Security Contacts",
                "template": 'site:{domain} inurl:security.txt OR inurl:"security-txt" OR inurl:disclosure',
                "explanation": "Checks for RFC 9116 security.txt vulnerability disclosure policies and PGP keys.",
                "operators": ["site:", "inurl:"]
            }
        ]
    },
    {
        "id": "tech_discovery",
        "title": "9. Technology and Platform Discovery",
        "icon": "bi-cpu",
        "badge_color": "success",
        "description": "Fingerprint CMS platforms, cloud infrastructure, third-party libraries, and web frameworks.",
        "queries": [
            {
                "name": "WordPress Footprint",
                "template": 'site:{domain} inurl:wp-content OR inurl:wp-includes OR inurl:wp-json',
                "explanation": "Detects WordPress installations, installed plugins, and theme assets.",
                "operators": ["site:", "inurl:"]
            },
            {
                "name": "Drupal & Joomla Platforms",
                "template": 'site:{domain} inurl:"node/" OR inurl:"modules/" OR inurl:"components/com_"',
                "explanation": "Identifies legacy or modern Drupal and Joomla CMS footprints.",
                "operators": ["site:", "inurl:"]
            },
            {
                "name": "Swagger / OpenAPI Documentation",
                "template": 'site:{domain} inurl:swagger OR inurl:api-docs OR inurl:"openapi.json"',
                "explanation": "Finds interactive API documentation detailing schema endpoints and parameters.",
                "operators": ["site:", "inurl:"]
            },
            {
                "name": "Cloud Storage Buckets & CDNs",
                "template": 'site:{domain} intext:"s3.amazonaws.com" OR intext:"blob.core.windows.net" OR intext:"storage.googleapis.com"',
                "explanation": "Identifies linked cloud object storage assets used for static media or downloads.",
                "operators": ["site:", "intext:"]
            }
        ]
    },
    {
        "id": "backups",
        "title": "10. Publicly Indexed Backup References",
        "icon": "bi-archive",
        "badge_color": "warning",
        "description": "Search for exposed source archives, database dumps, and backup files (.bak, .sql, .zip).",
        "queries": [
            {
                "name": "Database Dumps & SQL Scripts",
                "template": 'site:{domain} filetype:sql OR filetype:dump OR inurl:dump.sql',
                "explanation": "Scans for database schema and data exports left in web roots.",
                "operators": ["site:", "filetype:", "inurl:"]
            },
            {
                "name": "Archive & Compressed Backups",
                "template": 'site:{domain} filetype:zip OR filetype:tar OR filetype:tar.gz OR filetype:tgz OR filetype:7z inurl:backup',
                "explanation": "Discovers archived site snapshots, web roots, and source backups.",
                "operators": ["site:", "filetype:", "inurl:"]
            },
            {
                "name": "Editor & System Backup Files",
                "template": 'site:{domain} filetype:bak OR filetype:old OR filetype:temp OR filetype:backup',
                "explanation": "Finds file copies created automatically by text editors, deployment scripts, or admins.",
                "operators": ["site:", "filetype:"]
            },
            {
                "name": "Git & SVN Version Control Exposure",
                "template": 'site:{domain} inurl:".git" OR inurl:".svn" OR inurl:".gitlab-ci.yml"',
                "explanation": "Searches for improperly configured web directories exposing version control trees.",
                "operators": ["site:", "inurl:"]
            }
        ]
    }
]

def generate_osint_queries(target_domain):
    """
    Takes a domain (e.g. 'example.com'), cleans it, and generates all 10 categories
    of Google dork queries with direct search links and meta explanations.
    """
    clean_domain = sanitize_domain(target_domain)
    if not clean_domain:
        return {"error": "Invalid or empty domain provided.", "categories": [], "total_queries": 0}
        
    result_categories = []
    total_query_count = 0
    
    for cat in OSINT_CATEGORIES:
        cat_queries = []
        for q in cat["queries"]:
            rendered_query = q["template"].replace("{domain}", clean_domain)
            google_url = "https://www.google.com/search?q=" + urllib.parse.quote_plus(rendered_query)
            
            cat_queries.append({
                "name": q["name"],
                "query": rendered_query,
                "explanation": q["explanation"],
                "operators": q["operators"],
                "google_url": google_url
            })
            total_query_count += 1
            
        result_categories.append({
            "id": cat["id"],
            "title": cat["title"],
            "icon": cat["icon"],
            "badge_color": cat["badge_color"],
            "description": cat["description"],
            "query_count": len(cat_queries),
            "queries": cat_queries
        })
        
    return {
        "domain": clean_domain,
        "total_queries": total_query_count,
        "categories": result_categories,
        "disclaimer": "All generated queries are intended strictly for authorized security auditing, reconnaissance research, and asset inventory. Presence of a query does not imply vulnerability or exposure."
    }


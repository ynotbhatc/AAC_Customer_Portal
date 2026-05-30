-- 003a_taxonomy_seed.sql
--
-- Initial bucket + vendor taxonomy. Operators extend / edit this
-- through the admin UI or by direct SQL; the seed gives a fresh install
-- something useful to classify against.
--
-- Idempotent — uses ON CONFLICT (key) DO UPDATE for both tables so
-- re-running the seed picks up new aliases / cpe keys.

-- ── buckets ────────────────────────────────────────────────────────────
INSERT INTO buckets (key, display_name, bucket_type, sort_order, description) VALUES
  ('rhel',                'Red Hat Enterprise Linux', 'os',          10, 'RHEL 7/8/9/10 + derivatives'),
  ('rocky',               'Rocky Linux',              'os',          11, 'Rocky Linux 8/9'),
  ('alma',                'AlmaLinux',                'os',          12, 'AlmaLinux 8/9'),
  ('oracle_linux',        'Oracle Linux',             'os',          13, 'Oracle Linux 7/8/9'),
  ('centos',              'CentOS',                   'os',          14, 'CentOS 7 (legacy)'),
  ('ubuntu',              'Ubuntu',                   'os',          20, 'Ubuntu LTS server'),
  ('debian',              'Debian',                   'os',          21, 'Debian stable'),
  ('suse',                'SUSE / openSUSE',          'os',          22, 'SLES + openSUSE Leap'),
  ('amazon_linux',        'Amazon Linux',             'os',          23, 'Amazon Linux 2 + 2023'),
  ('windows_server',      'Windows Server',           'os',          30, 'Windows Server 2016/2019/2022/2025'),
  ('windows_workstation', 'Windows (workstation)',    'os',          31, 'Windows 10/11 client'),
  ('macos',               'macOS',                    'os',          32, 'macOS endpoints'),
  ('container_runtime',   'Container Runtime',        'container',   40, 'Docker, Podman, containerd, CRI-O'),
  ('kubernetes',          'Kubernetes',               'container',   41, 'Upstream K8s + distros (OCP, EKS, AKS, GKE)'),
  ('cloud_aws',           'AWS Services',             'cloud',       50, 'AWS-managed services + SDKs'),
  ('cloud_azure',         'Azure Services',           'cloud',       51, 'Azure-managed services + SDKs'),
  ('cloud_gcp',           'GCP Services',             'cloud',       52, 'Google Cloud services + SDKs'),
  ('network_os',          'Network OS',               'network',     60, 'Cisco IOS/NX-OS, Juniper Junos, Arista EOS, VyOS, MikroTik'),
  ('firewall',            'Firewalls / Next-Gen FW',  'network',     61, 'Palo Alto, Fortinet, Check Point, pfSense'),
  ('load_balancer',       'Load Balancers / ADC',     'network',     62, 'F5 BIG-IP, NetScaler/Citrix ADC, HAProxy, NGINX Plus'),
  ('ot_scada',            'OT / SCADA',               'ot',          70, 'Siemens, Schneider, Rockwell, ABB, GE OT/ICS'),
  ('ot_smart_meter',      'AMI / Smart Meter',        'ot',          71, 'AMI head-ends, smart meter firmware'),
  ('middleware_web',      'Web Servers',              'middleware',  80, 'Apache, NGINX, IIS, Tomcat'),
  ('middleware_db',       'Databases',                'middleware',  81, 'PostgreSQL, MySQL/MariaDB, Oracle DB, SQL Server, MongoDB, Redis'),
  ('middleware_mq',       'Message Brokers',          'middleware',  82, 'Kafka, RabbitMQ, ActiveMQ'),
  ('runtime_jvm',         'JVM Runtimes',             'runtime',     90, 'OpenJDK, Oracle Java, Eclipse Temurin'),
  ('runtime_python',      'Python Runtimes',          'runtime',     91, 'CPython, PyPy + critical libraries'),
  ('runtime_node',        'Node.js Runtime',          'runtime',     92, 'Node.js + critical npm packages'),
  ('app_devtools',        'Dev Tools / CI',           'app',        100, 'GitLab, Jenkins, GitHub Enterprise, Bitbucket'),
  ('app_collaboration',   'Collaboration',            'app',        101, 'Confluence, Jira, SharePoint, MS Teams'),
  ('app_vmware',          'VMware Platform',          'app',        110, 'vSphere/ESXi/vCenter/Workspace ONE'),
  ('app_ansible',         'Ansible Automation',       'app',        111, 'AAP/Tower/AWX/EDA/Hub/Galaxy'),
  ('mobile',              'Mobile / iOS / Android',   'app',        120, 'Mobile platform-level CVEs')
ON CONFLICT (key) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description  = EXCLUDED.description,
    bucket_type  = EXCLUDED.bucket_type,
    sort_order   = EXCLUDED.sort_order;

-- ── vendors ────────────────────────────────────────────────────────────
INSERT INTO vendors (key, display_name, aliases, cpe_vendor_keys, advisory_id_pattern, psirt_url) VALUES
  ('redhat',         'Red Hat',                ARRAY['Red Hat','Red Hat, Inc.','RedHat'],                       ARRAY['redhat','red_hat'],   'RHSA-\d{4}:\d+', 'https://access.redhat.com/security/security-updates/'),
  ('rocky',          'Rocky Enterprise Software Foundation', ARRAY['Rocky','Rocky Linux','RESF'],               ARRAY['rocky','rockylinux'], 'RXSA-\d+',       NULL),
  ('alma',           'AlmaLinux OS Foundation', ARRAY['AlmaLinux','AlmaLinux OS','Alma'],                       ARRAY['almalinux','alma'],   'ALSA-\d+',       NULL),
  ('oracle',         'Oracle',                 ARRAY['Oracle','Oracle Corporation','Oracle Corp'],              ARRAY['oracle'],             'ELSA-\d+',       'https://www.oracle.com/security-alerts/'),
  ('centos',         'CentOS',                 ARRAY['CentOS','CentOS Project'],                                ARRAY['centos'],             'CESA-\d+',       NULL),
  ('canonical',      'Canonical',              ARRAY['Ubuntu','Canonical','Canonical Ltd.'],                    ARRAY['canonical','ubuntu'], 'USN-\d+-\d+',    'https://ubuntu.com/security/notices'),
  ('debian',         'Debian',                 ARRAY['Debian','Debian Project'],                                ARRAY['debian'],             'DSA-\d+-\d+',    'https://www.debian.org/security/'),
  ('suse',           'SUSE',                   ARRAY['SUSE','SUSE LLC','openSUSE','SuSE'],                      ARRAY['suse','opensuse'],    'SUSE-SU-\d{4}:\d+', 'https://www.suse.com/support/security/'),
  ('amazon',         'Amazon',                 ARRAY['Amazon','Amazon Web Services','AWS','Amazon Linux'],      ARRAY['amazon','amazon_aws'],'ALAS\d?-\d+-\d+',   'https://alas.aws.amazon.com/'),
  ('microsoft',      'Microsoft',              ARRAY['Microsoft','Microsoft Corporation'],                      ARRAY['microsoft'],          'KB\d+|MS\d{2}-\d+', 'https://msrc.microsoft.com/'),
  ('apple',          'Apple',                  ARRAY['Apple','Apple Inc.'],                                     ARRAY['apple'],              NULL,                'https://support.apple.com/en-us/HT201222'),
  ('google',         'Google',                 ARRAY['Google','Google LLC','Google Cloud'],                     ARRAY['google'],             NULL,                'https://cloud.google.com/support/bulletins'),
  ('docker',         'Docker',                 ARRAY['Docker','Docker, Inc.'],                                  ARRAY['docker'],             NULL,                NULL),
  ('kubernetes',     'Kubernetes',             ARRAY['Kubernetes','CNCF','Cloud Native Computing Foundation'],  ARRAY['kubernetes'],         NULL,                NULL),
  ('cisco',          'Cisco',                  ARRAY['Cisco','Cisco Systems'],                                  ARRAY['cisco'],              'cisco-sa-\S+',      'https://sec.cloudapps.cisco.com/security/center/publicationListing.x'),
  ('juniper',        'Juniper Networks',       ARRAY['Juniper','Juniper Networks'],                             ARRAY['juniper'],            'JSA\d+',            'https://supportportal.juniper.net/JSAList'),
  ('arista',         'Arista Networks',        ARRAY['Arista','Arista Networks'],                               ARRAY['arista'],             NULL,                NULL),
  ('vyos',           'VyOS',                   ARRAY['VyOS'],                                                   ARRAY['vyos'],               NULL,                NULL),
  ('mikrotik',       'MikroTik',               ARRAY['MikroTik','Mikrotik'],                                    ARRAY['mikrotik'],           NULL,                NULL),
  ('paloalto',       'Palo Alto Networks',     ARRAY['Palo Alto','Palo Alto Networks','PAN'],                   ARRAY['paloaltonetworks','palo_alto_networks'], NULL, 'https://security.paloaltonetworks.com/'),
  ('fortinet',       'Fortinet',               ARRAY['Fortinet'],                                               ARRAY['fortinet'],           'FG-IR-\S+',         'https://www.fortiguard.com/psirt'),
  ('checkpoint',     'Check Point',            ARRAY['Check Point','CheckPoint'],                               ARRAY['checkpoint','check_point'], NULL,           NULL),
  ('f5',             'F5',                     ARRAY['F5','F5 Networks','F5 Inc'],                              ARRAY['f5'],                 'K\d+',              'https://my.f5.com/manage/s/article/K57821111'),
  ('citrix',         'Citrix',                 ARRAY['Citrix','Citrix Systems'],                                ARRAY['citrix'],             'CTX\d+',            'https://support.citrix.com/'),
  ('siemens',        'Siemens',                ARRAY['Siemens','Siemens AG'],                                   ARRAY['siemens'],            'SSA-\d+',           'https://cert-portal.siemens.com/productcert/'),
  ('schneider',      'Schneider Electric',     ARRAY['Schneider','Schneider Electric'],                         ARRAY['schneider-electric','schneider_electric'], 'SEVD-\d{4}-\S+', 'https://www.se.com/ww/en/work/support/cybersecurity/'),
  ('rockwell',       'Rockwell Automation',    ARRAY['Rockwell','Rockwell Automation','Allen-Bradley'],         ARRAY['rockwellautomation','rockwell-automation'], NULL, 'https://www.rockwellautomation.com/en-us/trust-center/security-advisories.html'),
  ('abb',            'ABB',                    ARRAY['ABB'],                                                    ARRAY['abb'],                NULL,                NULL),
  ('ge',             'GE',                     ARRAY['GE','General Electric','GE Digital'],                     ARRAY['ge','gedigital'],     NULL,                NULL),
  ('vmware',         'VMware',                 ARRAY['VMware','VMware, Inc.','Broadcom'],                       ARRAY['vmware'],             'VMSA-\d{4}-\d+',    'https://www.vmware.com/security/advisories.html'),
  ('atlassian',      'Atlassian',              ARRAY['Atlassian'],                                              ARRAY['atlassian'],          NULL,                'https://confluence.atlassian.com/security'),
  ('gitlab',         'GitLab',                 ARRAY['GitLab','GitLab Inc.'],                                   ARRAY['gitlab'],             NULL,                'https://about.gitlab.com/releases/categories/releases/'),
  ('jenkins',        'Jenkins',                ARRAY['Jenkins','Jenkins Project','CloudBees'],                  ARRAY['jenkins'],            NULL,                'https://www.jenkins.io/security/advisories/'),
  ('apache',         'Apache',                 ARRAY['Apache','Apache Software Foundation','ASF'],              ARRAY['apache'],             NULL,                NULL),
  ('nginx',          'NGINX / F5',             ARRAY['NGINX','F5 NGINX'],                                       ARRAY['nginx','f5'],         NULL,                NULL),
  ('postgresql',     'PostgreSQL',             ARRAY['PostgreSQL','PostgreSQL Global Development Group'],       ARRAY['postgresql'],         NULL,                'https://www.postgresql.org/support/security/'),
  ('mariadb',        'MariaDB',                ARRAY['MariaDB','MariaDB Foundation'],                           ARRAY['mariadb'],            NULL,                NULL),
  ('mongodb',        'MongoDB',                ARRAY['MongoDB','MongoDB Inc.'],                                 ARRAY['mongodb'],            NULL,                NULL),
  ('redis',          'Redis',                  ARRAY['Redis','Redis Labs'],                                     ARRAY['redis'],              NULL,                NULL),
  ('elastic',        'Elastic',                ARRAY['Elastic','Elastic NV','Elasticsearch BV'],                ARRAY['elastic','elasticsearch'], NULL,           'https://discuss.elastic.co/c/announcements/security-announcements/31'),
  ('python',         'Python Software Foundation', ARRAY['Python','Python Software Foundation','PSF'],          ARRAY['python'],             NULL,                NULL),
  ('nodejs',         'Node.js',                ARRAY['Node.js','OpenJS Foundation','Joyent'],                   ARRAY['nodejs'],             NULL,                'https://nodejs.org/en/blog/vulnerability/'),
  ('eclipse',        'Eclipse Foundation',     ARRAY['Eclipse','Eclipse Foundation','Eclipse Temurin'],         ARRAY['eclipse'],            NULL,                NULL),
  ('redhat_ansible', 'Red Hat Ansible',        ARRAY['Ansible','Red Hat Ansible','AWX','EDA'],                  ARRAY['redhat','ansible'],   NULL,                NULL)
ON CONFLICT (key) DO UPDATE SET
    display_name        = EXCLUDED.display_name,
    aliases             = EXCLUDED.aliases,
    cpe_vendor_keys     = EXCLUDED.cpe_vendor_keys,
    advisory_id_pattern = EXCLUDED.advisory_id_pattern,
    psirt_url           = EXCLUDED.psirt_url;

-- ── bucket_vendor_links ────────────────────────────────────────────────
-- Wire each vendor to the buckets it primarily belongs to. A vendor can
-- legitimately span multiple buckets (Red Hat = rhel + middleware + app).
INSERT INTO bucket_vendor_links (bucket_id, vendor_id)
SELECT b.id, v.id
FROM (VALUES
    ('rhel',                'redhat'),
    ('rhel',                'redhat_ansible'),
    ('rocky',               'rocky'),
    ('alma',                'alma'),
    ('oracle_linux',        'oracle'),
    ('centos',              'centos'),
    ('ubuntu',              'canonical'),
    ('debian',              'debian'),
    ('suse',                'suse'),
    ('amazon_linux',        'amazon'),
    ('windows_server',      'microsoft'),
    ('windows_workstation', 'microsoft'),
    ('macos',               'apple'),
    ('container_runtime',   'docker'),
    ('kubernetes',          'kubernetes'),
    ('kubernetes',          'redhat'),       -- OpenShift
    ('cloud_aws',           'amazon'),
    ('cloud_azure',         'microsoft'),
    ('cloud_gcp',           'google'),
    ('network_os',          'cisco'),
    ('network_os',          'juniper'),
    ('network_os',          'arista'),
    ('network_os',          'vyos'),
    ('network_os',          'mikrotik'),
    ('firewall',            'paloalto'),
    ('firewall',            'fortinet'),
    ('firewall',            'checkpoint'),
    ('firewall',            'cisco'),
    ('load_balancer',       'f5'),
    ('load_balancer',       'citrix'),
    ('load_balancer',       'nginx'),
    ('ot_scada',            'siemens'),
    ('ot_scada',            'schneider'),
    ('ot_scada',            'rockwell'),
    ('ot_scada',            'abb'),
    ('ot_scada',            'ge'),
    ('middleware_web',      'apache'),
    ('middleware_web',      'nginx'),
    ('middleware_web',      'microsoft'),    -- IIS
    ('middleware_db',       'postgresql'),
    ('middleware_db',       'mariadb'),
    ('middleware_db',       'oracle'),
    ('middleware_db',       'microsoft'),    -- SQL Server
    ('middleware_db',       'mongodb'),
    ('middleware_db',       'redis'),
    ('middleware_db',       'elastic'),
    ('middleware_mq',       'apache'),       -- Kafka, ActiveMQ
    ('runtime_jvm',         'oracle'),
    ('runtime_jvm',         'eclipse'),
    ('runtime_jvm',         'redhat'),
    ('runtime_python',      'python'),
    ('runtime_node',        'nodejs'),
    ('app_devtools',        'gitlab'),
    ('app_devtools',        'jenkins'),
    ('app_collaboration',   'atlassian'),
    ('app_collaboration',   'microsoft'),
    ('app_vmware',          'vmware'),
    ('app_ansible',         'redhat_ansible'),
    ('mobile',              'apple'),
    ('mobile',              'google')
) AS s(bucket_key, vendor_key)
JOIN buckets b ON b.key = s.bucket_key
JOIN vendors v ON v.key = s.vendor_key
ON CONFLICT DO NOTHING;

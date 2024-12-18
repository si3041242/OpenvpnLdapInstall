#!/bin/bash

# Color definitions
GREEN='\E[1;32m'
RED='\E[1;31m'
RES='\E[0m'

# 配置文件路径
SLAPD_CONF="/etc/ldap/slapd.conf"
EASYRSA_PATH="/opt/vpn-worker"
LDIF_PATH="/root/ldif/adduser"
Client_Cert_Date=3650

# 生成随机密码
generate_password() {
    < /dev/urandom tr -dc 'A-Za-z0-9' | head -c 20
}

# 从slapd.conf读取配置
parse_slapd_conf() {
    # 读取DC值
    local suffix=$(grep "^suffix" "$SLAPD_CONF" | cut -d'"' -f2)
    DC1=$(echo $suffix | cut -d',' -f1 | cut -d'=' -f2)
    DC2=$(echo $suffix | cut -d',' -f2 | cut -d'=' -f2)
    
    # 读取管理员DN和密码
    ADMIN_DN=$(grep "^rootdn" "$SLAPD_CONF" | cut -d'"' -f2)
    LDAP_PASS=$(grep "^rootpw" "$SLAPD_CONF" | awk '{print $2}')
    
    # 设置默认OU
    DEFAULT_OU=$DC1
    
    # 验证配置
    if [ -z "$DC1" ] || [ -z "$DC2" ] || [ -z "$LDAP_PASS" ]; then
        echo -e "${RED}Error: Cannot parse LDAP configuration${RES}"
        exit 1
    fi
}

# 验证邮箱格式
validate_email() {
    local email=$1
    if [[ ! "$email" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
        echo -e "${RED}Invalid email format${RES}"
        return 1
    fi
    return 0
}

# 创建 LDIF 文件修改
create_ldif() {
    local username=$1
    local usermail=$2
    local ou=$3
    local privilege=$4
    local password=$5
    
    cat > "$LDIF_PATH/add_user_${username}.ldif" << EOF
dn: uid=$username,ou=$ou,dc=$DC1,dc=$DC2
objectClass: inetOrgPerson
objectClass: top
cn: $username
sn: $username
mail: $usermail
uid: $username
userPassword: $password
privilege: $privilege
EOF
}

create_client_cert() {
    local username=$1
    cd $EASYRSA_PATH

    # 确保 pki 已经初始化
    [ ! -f "pki/private/ca.key" ] && {
        echo "PKI not initialized. Run './easyrsa init-pka' first."
        return 1
    }
    export EASYRSA_REQ_CN="$username"
    export EASYRSA_CERT_EXPIRE=${Client_Cert_Date}

    # 生成客户端密钥和请求
    EASYRSA_BATCH=1 ./easyrsa gen-req "$username" nopass
    
    # 签名客户端证书
    EASYRSA_BATCH=1 ./easyrsa sign-req client "$username"

    # 验证文件
    [ ! -f "pki/issued/${username}.crt" ] && {
        echo "Certificate file missing!"
        return 1
    }
    [ ! -f "pki/private/${username}.key" ] && {
        echo "Key file missing!"
        return 1
    }

    echo "Certificate and key generated successfully for $username"
}

# 新增邮件发送函数
send_config() {
    local username=$1
    local email=$2
    cd $EASYRSA_PATH/clients

    echo "Packaging configuration files..."
    tar -czf ${username}-vpn-config.tar.gz ${username}

    # 创建使用指南
    cat > vpn-guide.txt << EOF
OpenVPN Configuration Guide
==========================

1. Install OpenVPN Client
------------------------
Option 1: Desktop Client
- Download from: https://openvpn.net/client/
- Available for Windows, macOS, and Linux

Option 2: Mobile Client
- Android: Install "OpenVPN Connect" from Google Play Store
- iOS: Install "OpenVPN Connect" from App Store

2. Import Configuration
----------------------
1. Open OpenVPN client
2. Select "Import" or "+" button
3. Choose the .ovpn file from ${username}-vpn-config.tar.gz
4. Enter your credentials when prompted:
   - Username: ${username}
   - Password: ${password}

3. Connect to VPN
----------------
1. Select the imported profile
2. Click "Connect" button
3. Wait for connection to establish

For any issues, please contact support.
EOF

    # 发送邮件
    echo "Sending configuration via email..."
    mutt -s "${username} VPN Access" \
         -a ${username}-vpn-config.tar.gz \
         -a vpn-guide.txt \
         -- ${email} << EOF
Hello,

Your VPN access has been configured. Please find attached:
1. Your VPN configuration file (${username}-vpn-config.tar.gz)
2. Installation and configuration guide (vpn-guide.txt)

Best regards,
VPN Admin
EOF

    # 清理临时文件
    rm -f ${username}-vpn-config.tar.gz vpn-guide.txt
}

# 主函数
main() {
    # 检查配置文件
    if [ ! -f "$SLAPD_CONF" ]; then
        echo -e "${RED}Error: SLAPD configuration file not found${RES}"
        exit 1
    fi

    # 解析配置
    parse_slapd_conf

    # 创建必要目录
    mkdir -p $LDIF_PATH


    echo -e "${GREEN}=== OpenVPN User Creation ===${RES}"

    # 用户输入
    read -p "Input username: " username
    [ -z "$username" ] && { echo "Username cannot be empty"; exit 1; }

    # 邮箱输入和验证
    while true; do
        read -p "Input email: " usermail
        if [ -z "$usermail" ]; then
            echo "Email cannot be empty"
            continue
        fi
        if validate_email "$usermail"; then
            break
        fi
    done

    read -p "Input OU [gems]: " ou
    ou=${ou:-$DEFAULT_OU}

    read -p "Input privilege [gems]: " privilege
    privilege=${privilege:-"gems"}

    # 生成随机密码
    password=$(generate_password)
    
    echo -e "${GREEN}Creating LDAP user...${RES}"
    create_ldif "$username" "$usermail" "$ou" "$privilege" "$password"
    
    # 添加用户
    ldapadd -x -D "cn=admin,dc=$DC1,dc=$DC2" -w  ${LDAP_PASS} -H ldapi:/// -f "$LDIF_PATH/add_user_${username}.ldif"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}LDAP user created successfully${RES}"
        
        echo -e "${GREEN}Generating OpenVPN certificates...${RES}"
        if create_client_cert "$username"; then
            # 调用 make_config.sh 生成配置文件
            ./make_config.sh "$username"
            
            if [ -f "$EASYRSA_PATH/clients/$username/${username}.ovpn" ]; then
                echo -e "${GREEN}=== User Creation Completed ===${RES}"
                echo "Username: $username"
                echo "Password: $password"
                echo "Email: $usermail"
                echo "OU: $ou"
                echo "Privilege: $privilege"
                echo "Config file: $EASYRSA_PATH/clients/$username/${username}.ovpn"
            else
                echo -e "${RED}Error: Configuration file generation failed${RES}"
                exit 1
            fi
        else
            echo -e "${RED}Error: Client certificate creation failed${RES}"
            exit 1
        fi
    else
        echo -e "${RED}Error: LDAP user creation failed${RES}"
        exit 1
    fi
    if [ -f "$EASYRSA_PATH/clients/$username/${username}.ovpn" ]; then
        echo -e "${GREEN}=== User Creation Completed ===${RES}"
        echo "Username: $username"
        echo "Password: $password"
        echo "Email: $usermail"
        echo "OU: $ou"
        echo "Privilege: $privilege"
        
        # 发送配置文件
        send_config "$username" "$usermail" || {
            echo -e "${RED}Error: Failed to send configuration email${RES}"
        }
    else
        echo -e "${RED}Error: Configuration file generation failed${RES}"
        exit 1
    fi
}
main
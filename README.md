# OpenvpnLdapInstall
ubuntu22.04版本测试通过
sh或者bash 脚本 后面跟参数 install或者delete

delete会清除所有vpn和ldap环境

3.5版本的openvpn connect 取消了auth-nocache参数，具体信息参考
https://support.openvpn.com/hc/en-us/articles/29749500637467-OpenVPN-Connect-Required-credentials-are-missing-and-NEED-CREDS-FATAL-ERR

修改了服务端和客户端的加密方式 从CDB改为GCM

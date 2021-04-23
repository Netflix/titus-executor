package docker

import (
	"archive/tar"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/Netflix/titus-executor/config"
	runtimeTypes "github.com/Netflix/titus-executor/executor/runtime/types"
	log "github.com/sirupsen/logrus"
)

const sshdConfig = `
# See the sshd_config(5) manpage for details

# What ports, IPs and protocols we listen for
Port 7522
# Use these options to restrict which interfaces/protocols sshd will bind to
#ListenAddress ::
#ListenAddress 0.0.0.0
Protocol 2
# HostKeys for protocol version 2
HostKey /titus/sshd/etc/ssh/ssh_host_rsa_key
HostCertificate /run/metatron/certificates/ssh_host_rsa_key-cert.pub

# Logging
SyslogFacility AUTH
LogLevel INFO

# Authentication:
LoginGraceTime 120
PermitRootLogin without-password
StrictModes yes

PubkeyAuthentication yes
AuthorizedKeysFile	/titus/ssh_keys/%u

TrustedUserCAKeys /titus/etc/ssh/trusted_user_ca_keys.pub
AuthorizedPrincipalsFile /titus/etc/ssh/authorized_principals_%u

# Don't read the user's ~/.rhosts and ~/.shosts files
IgnoreRhosts yes
# similar for protocol version 2
HostbasedAuthentication no
# Uncomment if you don't trust ~/.ssh/known_hosts for RhostsRSAAuthentication
#IgnoreUserKnownHosts yes

# To enable empty passwords, change to yes (NOT RECOMMENDED)
PermitEmptyPasswords no

# Change to yes to enable challenge-response passwords (beware issues with
# some PAM modules and threads)
ChallengeResponseAuthentication no

# Change to no to disable tunnelled clear text passwords
PasswordAuthentication no

# Kerberos options
#KerberosAuthentication no
#KerberosGetAFSToken no
#KerberosOrLocalPasswd yes
#KerberosTicketCleanup yes

# GSSAPI options
#GSSAPIAuthentication no
#GSSAPICleanupCredentials yes

X11Forwarding no
X11DisplayOffset 10
PrintMotd no
PrintLastLog no
TCPKeepAlive yes
#UseLogin no

#MaxStartups 10:30:60
#Banner /etc/issue.net

# Allow client to pass locale environment variables
AcceptEnv LANG LC_*

Subsystem sftp /titus/sshd/usr/lib64/misc/sftp-server

PidFile /dev/null
`

func addContainerSSHDConfig(c runtimeTypes.Container, tw *tar.Writer, cfg config.Config) error {
	caData, err := ioutil.ReadFile(cfg.ContainerSSHDCAFile)
	if err != nil {
		return err
	}
	return addContainerSSHDConfigWithData(c, tw, cfg, caData)
}

func addContainerSSHDConfigWithData(c runtimeTypes.Container, tw *tar.Writer, cfg config.Config, caData []byte) error {
	sshConfigBytes := []byte(sshdConfig)
	err := tw.WriteHeader(&tar.Header{
		Name: "/titus/etc/ssh/sshd_config",
		Mode: 0644,
		Size: int64(len(sshConfigBytes)),
	})
	if err != nil {
		return err
	}
	_, err = tw.Write(sshConfigBytes)
	if err != nil {
		return err
	}

	err = tw.WriteHeader(&tar.Header{
		Name: "/titus/etc/ssh/trusted_user_ca_keys.pub",
		Mode: 0644,
		Size: int64(len(caData)),
	})
	if err != nil {
		return err
	}
	_, err = tw.Write(caData)
	if err != nil {
		return err
	}

	containerEnv := c.Env()["NETFLIX_ENVIRONMENT"]
	if containerEnv == "" {
		log.Warn("The NETFLIX_ENVIRONMENT variable is not set. SSH access to the container may not be available!")
	}

	users := append(cfg.ContainerSSHDUsers, c.AppName())
	for _, username := range users {
		lines := []string{
			"# Principals should match the pattern used by the BLESS service. Visit go/bless for details.",
			"BLESS_EMERGENCY_USE_BACKDOOR",
		}
		if containerEnv != "" {
			lines = append(lines, fmt.Sprintf("~v3:titus:%s:%s:%s:%s:%s:%s", username, c.AppName(), containerEnv, c.TaskID(), c.JobGroupStack(), c.JobGroupDetail()))
		}
		line := []byte(strings.Join(lines, "\n"))
		err = tw.WriteHeader(&tar.Header{
			Name: fmt.Sprintf("/titus/etc/ssh/authorized_principals_%s", username),
			Mode: 0644,
			Size: int64(len(line)),
		})
		if err != nil {
			return err
		}
		_, err = tw.Write(line)
		if err != nil {
			return err
		}
	}
	return nil
}

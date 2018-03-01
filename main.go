package main

import (
	"./model"
	"./webserver"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type JenkinsKeycloakConfig struct {
	Realm         string `json:"realm"`
	AuthServerURL string `json:"auth-server-url"`
	SslRequired   string `json:"ssl-required"`
	Resource      string `json:"resource"`
	PublicClient  bool   `json:"public-client"`
}

type SonarKeycloakConfig struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	TokenIntrospectionEndpoint                 string   `json:"token_introspection_endpoint"`
	UserinfoEndpoint                           string   `json:"userinfo_endpoint"`
	EndSessionEndpoint                         string   `json:"end_session_endpoint"`
	JwksURI                                    string   `json:"jwks_uri"`
	CheckSessionIframe                         string   `json:"check_session_iframe"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	SubjectTypesSupported                      []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported           []string `json:"id_token_signing_alg_values_supported"`
	UserinfoSigningAlgValuesSupported          []string `json:"userinfo_signing_alg_values_supported"`
	RequestObjectSigningAlgValuesSupported     []string `json:"request_object_signing_alg_values_supported"`
	ResponseModesSupported                     []string `json:"response_modes_supported"`
	RegistrationEndpoint                       string   `json:"registration_endpoint"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	ClaimsSupported                            []string `json:"claims_supported"`
	ClaimTypesSupported                        []string `json:"claim_types_supported"`
	ClaimsParameterSupported                   bool     `json:"claims_parameter_supported"`
	ScopesSupported                            []string `json:"scopes_supported"`
	RequestParameterSupported                  bool     `json:"request_parameter_supported"`
	RequestURIParameterSupported               bool     `json:"request_uri_parameter_supported"`
}

const labelName string = "com.github.joostvdg.name"
const labelDescription string = "com.github.joostvdg.description"
const labelWebPath string = "com.github.joostvdg.webPath"
const labelWebPort string = "com.github.joostvdg.webPort"

func main() {
	port := flag.String("keycloak-port", "8280", "Port number for the Keycloak server")
	action := flag.String("action", "generate-config", `
		- generate-config: Generate configuration files such as keycloak configuration for Jenkins
		- init-sonar: intialize the configuration of SonarQube, such as the keycloak configuration
		- list-docker: list docker containers part of this stack
		- serve: serve as webserver serving a html page with the docker container listing (same source as list-docker)
		`)
	flag.Parse()

	hostname, _ := os.Hostname()
	hostname = strings.ToLower("172.17.0.1") // windows might not care, but Keycloak certainly does!
	fmt.Printf("== Hostname found: %s\n", hostname)
	fmt.Printf("== Action to perform: %s\n", *action)
	switch *action {
	case "generate-config":
		fmt.Printf("== Keycloak Config for Jenkins\n-----------------\n")
		generateJenkinsKeycloakConfig(hostname, *port)
	case "init-sonar":
		fmt.Printf("== Keycloak Config for SonarQube\n-----------------\n")
		sonarKeycloakConfig := generateSonarKeycloakConfig(hostname, *port)
		fmt.Printf("-----------------\n")
		fmt.Printf("== Update Config of SonarQube\n-----------------\n")
		updateSonarQubeConfig(sonarKeycloakConfig, hostname)
	case "list-docker":

		labelFilter := fmt.Sprintf("%s=%s", "com.github.joostvdg.namespace", "cidc")
		containersList, err := containerList(labelFilter)
		containers := containerInfoList(containersList)

		if err != nil {
			fmt.Println(err.Error())
		} else if len(containers) == 0 {
			fmt.Printf("   > No Containers found with label filter %s\n", labelFilter)
		} else {
			fmt.Printf(" > We found these containers: \n")
			for _, container := range containers {
				if container.Name != "" {
					fmt.Printf("   > %s\n", container.String())
				}
			}
		}
	case "serve":
		serverPort := "8087"
		if len(os.Getenv("SERVER_PORT")) > 0 {
			serverPort = os.Getenv("SERVER_PORT")
		}
		fmt.Printf("=== STARTING WEB SERVER @%s\n", serverPort)
		fmt.Println("=============================================")

		labelFilter := fmt.Sprintf("%s=%s", "com.github.joostvdg.namespace", "cidc")
		containersList, _ := containerList(labelFilter)
		containers := containerInfoList(containersList)
		webserverData := &webserver.WebserverData{Containers: containers, Title: "CIDC Containers"}

		c := make(chan bool)
		go webserver.StartServer(serverPort, webserverData, c)
		fmt.Println("> Started the web server, now polling swarm")

		stop := make(chan os.Signal, 1)
		signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

		for i := 1; ; i++ { // this is still infinite
			t := time.NewTicker(time.Second * 30)
			select {
			case <-stop:
				fmt.Println("> Shutting down polling")
				break
			case <-t.C:
				fmt.Println("  > Updating Stacks")
				containersList, _ := containerList(labelFilter)
				containers := containerInfoList(containersList)
				webserverData.UpdateContainers(containers)
				continue
			}
			break // only reached if the quitCh case happens
		}
		fmt.Println("> Shutting down webserver")
		c <- true
		if b := <-c; b {
			fmt.Println("> Webserver shut down")
		}
		fmt.Println("> Shut down app")
	default:
		panic(fmt.Sprintf("Action '%v' not recognized\n", *action))
	}
	fmt.Printf("-----------------\n")
}

func containerInfoList(containers []types.Container) []model.ContainerInfo {
	var containerInfoList []model.ContainerInfo
	for _, container := range containers {
		ports := parsePorts(container)
		volumes := parseVolumes(container)
		cleanedImageName := container.Image
		containerInfo := model.ContainerInfo{
			Name:        strings.Replace(container.Labels[labelName], "\"", "", -1),
			Description: strings.Replace(container.Labels[labelDescription], "\"", "", -1),
			WebPort:     container.Labels[labelWebPort],
			WebPath:     container.Labels[labelWebPath],
			Ports:       ports,
			Volumes:     volumes,
			Created:     container.Created,
			Image:       cleanedImageName,
		}
		if strings.TrimSpace(containerInfo.Name) != "" {
			containerInfoList = append(containerInfoList, containerInfo)
		}
	}
	return containerInfoList
}

func parseVolumes(container types.Container) []string {
	volumes := make([]string, len(container.Mounts))
	for _, mount := range container.Mounts {
		volumes = append(volumes, fmt.Sprintf("%s @%s", mount.Name, mount.Destination))
	}
	return volumes
}

func parsePorts(container types.Container) []string {
	ports := make([]string, len(container.Ports))
	for _, port := range container.Ports {
		// Ugly, but it works: https://stackoverflow.com/questions/41787620/convert-uint64-to-string-in-golang
		ports = append(ports, fmt.Sprintf("%s:%s", strconv.Itoa(int(port.PublicPort)), strconv.Itoa(int(port.PrivatePort))))
	}
	return ports
}

func containerList(labelFilter string) ([]types.Container, error) {
	host := "unix:///var/run/docker.sock"
	fmt.Println(" > Probing Host: " + host)
	cli, err := client.NewClientWithOpts(client.WithVersion("1.35"))
	if err != nil {
		panic(err)
	}

	filter := filters.NewArgs()
	filter.Add("label", labelFilter) // TODO: make filter optional / parameter
	return cli.ContainerList(context.Background(), types.ContainerListOptions{Filters: filter})
}

func updateSonarQubeConfig(openidcConfig string, hostname string) {
	updateSonarQubeSettings("sonar.core.serverBaseURL", "http://localhost:8289/sonar", hostname, "8289")
	updateSonarQubeSettings("sonar.auth.oidc.clientId.secured", "sonarqube", hostname, "8289")
	updateSonarQubeSettings("sonar.auth.oidc.enabled", "true", hostname, "8289")
	updateSonarQubeSettings("sonar.auth.oidc.groupsSync", "true", hostname, "8289")
	updateSonarQubeSettings("sonar.auth.oidc.groupsSync.claimName", "groups", hostname, "8289")
	updateSonarQubeSettings("sonar.auth.oidc.providerConfiguration", openidcConfig, hostname, "8289")
}

func generateJenkinsKeycloakConfig(hostname string, port string) {
	realm := "ci"
	sslRequired := "external"
	resource := "jenkins"
	publicClient := true
	serverUrlTemplate := "http://XXX:YYY/auth"
	authServerUrl := replaceHostnameAndPort(serverUrlTemplate, hostname, port)
	config := JenkinsKeycloakConfig{
		Realm:         realm,
		SslRequired:   sslRequired,
		PublicClient:  publicClient,
		Resource:      resource,
		AuthServerURL: authServerUrl,
	}
	// Convert structs to JSON.
	data, err := json.Marshal(config)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", data)
}

func replaceHostnameAndPort(originalString string, hostname string, port string) string {
	returnString := strings.Replace(originalString, "XXX", hostname, 1)
	return strings.Replace(returnString, "YYY", port, 1)
}

func generateSonarKeycloakConfig(hostname string, port string) string {
	issuer := replaceHostnameAndPort("http://XXX:YYY/auth/realms/ci", hostname, port)
	authorizationEndpoint := replaceHostnameAndPort("http://XXX:YYY/auth/realms/ci/protocol/openid-connect/auth", hostname, port)
	tokenEndpoint := replaceHostnameAndPort("http://XXX:YYY/auth/realms/ci/protocol/openid-connect/token", hostname, port)
	tokenIntrospectionEndpoint := replaceHostnameAndPort("http://XXX:YYY/auth/realms/ci/protocol/openid-connect/token/introspect", hostname, port)
	userinfoEndpoint := replaceHostnameAndPort("http://XXX:YYY/auth/realms/ci/protocol/openid-connect/userinfo", hostname, port)
	endSessionEndpoint := replaceHostnameAndPort("http://XXX:YYY/auth/realms/ci/protocol/openid-connect/logout", hostname, port)
	jwksURI := replaceHostnameAndPort("http://XXX:YYY/auth/realms/ci/protocol/openid-connect/certs", hostname, port)
	checkSessionIframe := replaceHostnameAndPort("http://XXX:YYY/auth/realms/ci/protocol/openid-connect/login-status-iframe.html", hostname, port)
	grantTypesSupported := []string{"authorization_code", "implicit", "refresh_token", "password", "client_credentials"}
	responseTypesSupported := []string{"code", "none", "id_token", "token", "id_token token", "code id_token", "code token", "code id_token token"}
	subjectTypesSupported := []string{"public", "pairwise"}
	iDTokenSigningAlgValuesSupported := []string{"RS256"}
	userinfoSigningAlgValuesSupported := []string{"RS256"}
	requestObjectSigningAlgValuesSupported := []string{"none", "RS256"}
	responseModesSupported := []string{"query", "fragment", "form_post"}
	registrationEndpoint := replaceHostnameAndPort("http://XXX:YYY/auth/realms/ci/clients-registrations/openid-connect", hostname, port)
	tokenEndpointAuthMethodsSupported := []string{"private_key_jwt", "client_secret_basic", "client_secret_post"}
	tokenEndpointAuthSigningAlgValuesSupported := []string{"RS256"}
	claimsSupported := []string{"sub", "iss", "auth_time", "name", "given_name", "family_name", "preferred_username", "email"}
	claimTypesSupported := []string{"normal"}
	claimsParameterSupported := false
	scopesSupported := []string{"openid", "offline_access"}
	requestParameterSupported := true
	requestURIParameterSupported := true

	config := SonarKeycloakConfig{
		Issuer:                                     issuer,
		AuthorizationEndpoint:                      authorizationEndpoint,
		TokenEndpoint:                              tokenEndpoint,
		TokenIntrospectionEndpoint:                 tokenIntrospectionEndpoint,
		UserinfoEndpoint:                           userinfoEndpoint,
		EndSessionEndpoint:                         endSessionEndpoint,
		JwksURI:                                    jwksURI,
		CheckSessionIframe:                         checkSessionIframe,
		GrantTypesSupported:                        grantTypesSupported,
		ResponseTypesSupported:                     responseTypesSupported,
		SubjectTypesSupported:                      subjectTypesSupported,
		IDTokenSigningAlgValuesSupported:           iDTokenSigningAlgValuesSupported,
		UserinfoSigningAlgValuesSupported:          userinfoSigningAlgValuesSupported,
		RequestObjectSigningAlgValuesSupported:     requestObjectSigningAlgValuesSupported,
		ResponseModesSupported:                     responseModesSupported,
		RegistrationEndpoint:                       registrationEndpoint,
		TokenEndpointAuthMethodsSupported:          tokenEndpointAuthMethodsSupported,
		TokenEndpointAuthSigningAlgValuesSupported: tokenEndpointAuthSigningAlgValuesSupported,
		ClaimsSupported:                            claimsSupported,
		ClaimTypesSupported:                        claimTypesSupported,
		ClaimsParameterSupported:                   claimsParameterSupported,
		ScopesSupported:                            scopesSupported,
		RequestParameterSupported:                  requestParameterSupported,
		RequestURIParameterSupported:               requestURIParameterSupported,
	}

	// Convert structs to JSON.
	data, err := json.Marshal(config)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", data)
	openidcConfig := fmt.Sprintf("%s", data)
	return openidcConfig
}

func updateSonarQubeSettings(key string, value string, host string, port string) {
	fmt.Printf(">> Updating SonarQube settings: key=%v, value=%v\n", key, value)
	rawUrl := replaceHostnameAndPort("http://XXX:YYY/sonar/api/settings/set", host, port)
	var apiUrl *url.URL
	apiUrl, err := url.Parse(rawUrl)
	if err != nil {
		panic("boom")
	}

	parameters := url.Values{}
	parameters.Add("key", key)
	parameters.Add("value", value)
	apiUrl.RawQuery = parameters.Encode()
	urlStr := apiUrl.String()

	client := &http.Client{}
	r, _ := http.NewRequest("POST", urlStr, strings.NewReader("")) // <-- URL-encoded payload
	r.SetBasicAuth("admin", "admin")

	fmt.Printf(" > URL: %v\n", urlStr)
	resp, err := client.Do(r)
	if err != nil {
		fmt.Printf(" < Failed to update setting: %v", err)
	} else {
		fmt.Printf(" < %v\n", resp.Status)
	}

}

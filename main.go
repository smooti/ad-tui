package main

import (
	"fmt"

	"github.com/charmbracelet/log"
	"github.com/go-ldap/ldap/v3"
)

var client *ldap.Conn

const ldapServerURL = "ldap://localhost:1389"

var (
	username string = "user-1"
	password string = ""
	baseDN   string = "dc=example,dc=org"
)

// Initialize connection to server
func connect() error {
	var err error

	// For unencrypted LDAP (ldap://)
	client, err = ldap.DialURL(ldapServerURL)
	if err != nil {
		return fmt.Errorf("failed to dial LDAP server: %w", err)
	}
	log.Info("Successfully connected to LDAP server.")
	return nil
}

// Close connection if a connection was successful
func closeConnection() {
	if client != nil {
		client.Close()
		log.Info("Connection closed.")
	}
}

// Bind (Authenticate) user
func bindUser(username string, password string) error {
	if client == nil {
		return fmt.Errorf("not connected to LDAP server")
	}
	err := client.Bind(username, password)
	if err != nil {
		return fmt.Errorf("failed to bind as %s: %w", username, err)
	}
	log.Info("Sussesfully bound as %s", username)
	return nil
}

func searchEntries(searchBaseDN string, filter string, attributes []string) (*ldap.SearchResult, error) {
	if client == nil {
		return nil, fmt.Errorf("not connected to LDAP server")
	}

	searchRequest := ldap.NewSearchRequest(
		searchBaseDN,           // Base DN: The starting point of the search
		ldap.ScopeWholeSubtree, // Scope: Search the whole subtree (alternatives: ldap.ScopeSingleLevel, ldap.ScopeBaseObject)
		ldap.NeverDerefAliases, // DerefAliases: How to handle aliases
		0,                      // SizeLimit: Max number of entries to return (0 for server's default)
		0,                      // TimeLimit: Max time for search (0 for server's default)
		false,                  // TypesOnly: false to get values, true to get only types
		filter,                 // Filter: The LDAP search filter (e.g., "(objectClass=person)")
		attributes,             // Attributes: A list of attributes to retrieve (e.g., []string{"cn", "mail"})
		nil,                    // Controls: Optional LDAP controls
	)

	searchResult, err := client.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("search failed for filter '%s': %w", filter, err)
	}
	return searchResult, nil

}

// Get OU's of baseDN
// NOTE A Base query searches only the current path or object.
// A OneLevel query searches the immediate children of that path or object.
// A Subtree query searches the current path or object and all children of that path or object.
func searchForOUs(conn *ldap.Conn, baseDN string) (*ldap.SearchResult, error) {
	if client == nil {
		return nil, fmt.Errorf("not connected to LDAP server")
	}

	searchRequest := ldap.NewSearchRequest(
		baseDN,                             // Base DN: The starting point of the search
		ldap.ScopeSingleLevel,              // Scope: Search the whole subtree (alternatives: ldap.ScopeSingleLevel, ldap.ScopeBaseObject)
		ldap.NeverDerefAliases,             // DerefAliases: How to handle aliases
		0,                                  // SizeLimit: Max number of entries to return (0 for server's default)
		0,                                  // TimeLimit: Max time for search (0 for server's default)
		false,                              // TypesOnly: false to get values, true to get only types
		"(objectClass=organizationalUnit)", // Filter: The LDAP search filter (e.g., "(objectClass=person)")
		[]string{"ou, dn"},                 // Attributes: A list of attributes to retrieve (e.g., []string{"cn", "mail"})
		nil,                                // Controls: Optional LDAP controls
	)

	searchResult, err := conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}
	return searchResult, nil
}

func example1() {
	filter := "(objectClass=inetOrgPerson)"
	r, _ := searchEntries(baseDN, filter, []string{"uid", "cn"})
	for _, entry := range r.Entries {
		fmt.Printf("DN: %v\n", entry.DN)
		fmt.Printf("CN: %v\n", entry.GetAttributeValue("cn"))
		fmt.Printf("UID: %v\n", entry.GetAttributeValue("uid"))
		fmt.Println()
	}
}

func example2() {
	r, _ := searchForOUs(client, baseDN)
	for _, entry := range r.Entries {
		fmt.Println(entry.DN)
	}
}

func main() {
	// Connect to server
	if err := connect(); err != nil {
		log.Error("Initial connection failed: %v", err)
	}
	defer closeConnection()

	// Bind (Authenticate) if specified- Essential for write operations
	if username != "" && password != "" {
		if err := bindUser(username, password); err != nil {
			log.Error("Unable to bind as %s some operations might fail: %v", username, err)
		}
	} else {
		log.Info("Skipping authentication.")
	}

	example1()
	// example2()
}

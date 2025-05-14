package main

import (
	"fmt"
	"log"

	"github.com/go-ldap/ldap/v3"
)

// Global variable for the LDAP connection (for simplicity in examples)
var l *ldap.Conn

// Replace with your OpenLDAP server details
const ldapServerURL = "ldap://localhost:1389" // For unencrypted
// const ldapServerURL = "ldaps://localhost:636" // For LDAPS
const adminDN = "cn=admin,dc=example,dc=org"
const adminPassword = "adminpassword"
const baseDN = "dc=example,dc=org"

func connect() error {
	var err error

	// For unencrypted LDAP (ldap://)
	l, err = ldap.DialURL(ldapServerURL)
	if err != nil {
		return fmt.Errorf("failed to dial LDAP server: %w", err)
	}
	// Note: For production, always prefer LDAPS or StartTLS.

	// For LDAPS (ldaps://)
	// tlsConfig := &tls.Config{InsecureSkipVerify: true} // For testing with self-signed certs.
	// // For production, configure RootCAs, ServerName etc.
	// // tlsConfig := &tls.Config{
	// // 	ServerName: "your-ldap-server.com",
	// // 	// RootCAs: certPool, // Your CA certificate pool
	// // }
	// l, err = ldap.DialURL(ldapServerURL, ldap.DialWithTLSConfig(tlsConfig))
	// if err != nil {
	// 	return fmt.Errorf("failed to dial LDAPS server: %w", err)
	// }

	// Optional: For StartTLS (if connected via ldap:// initially)
	// if ldapServerURL_uses_ldap_schema { // conceptual check
	//    err = l.StartTLS(&tls.Config{InsecureSkipVerify: true}) // Use proper tls.Config for production
	//    if err != nil {
	//        l.Close()
	//        return fmt.Errorf("failed to start TLS: %w", err)
	//    }
	// }

	log.Println("Successfully connected to LDAP server.")
	return nil
}

// Call this at the end of your main function or when done
func closeConnection() {
	if l != nil {
		l.Close()
		log.Println("LDAP connection closed.")
	}
}

func bindUser(bindDN, password string) error {
	if l == nil {
		return fmt.Errorf("not connected to LDAP server")
	}
	err := l.Bind(bindDN, password)
	if err != nil {
		return fmt.Errorf("failed to bind as %s: %w", bindDN, err)
	}
	log.Printf("Successfully bound as %s", bindDN)
	return nil
}

func anonymousBind() error {
	if l == nil {
		return fmt.Errorf("not connected to LDAP server")
	}
	// For an anonymous bind, you typically just proceed with operations if the server allows.
	// Some libraries/servers might have an explicit anonymous bind, but with go-ldap/ldap/v3,
	// if you don't call Bind() with credentials, subsequent operations are anonymous.
	// You can also perform an explicit unauthenticated bind if needed for certain SASL mechanisms.
	// err := l.UnauthenticatedBind("") // Example for explicit unauthenticated
	// if err != nil {
	//     return fmt.Errorf("failed anonymous/unauthenticated bind: %w", err)
	// }
	log.Println("Proceeding with anonymous access (if server allows).")
	return nil
}

func searchEntries(searchBaseDN, filter string, attributes []string) (*ldap.SearchResult, error) {
	if l == nil {
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

	sr, err := l.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("search failed for filter '%s': %w", filter, err)
	}
	return sr, nil
}

// Example Usage of Search:
func findUserByUID(uid string) {
	filter := fmt.Sprintf("(&(objectClass=inetOrgPerson)(uid=%s))", ldap.EscapeFilter(uid))
	attributes := []string{"dn", "cn", "sn", "givenName", "mail", "uid"}
	sr, err := searchEntries(baseDN, filter, attributes)
	if err != nil {
		log.Printf("Error searching for user %s: %v", uid, err)
		return
	}

	if len(sr.Entries) == 0 {
		log.Printf("No user found with UID: %s", uid)
		return
	}

	log.Printf("Found %d entries for UID %s:", len(sr.Entries), uid)
	for _, entry := range sr.Entries {
		log.Printf("  DN: %s", entry.DN)
		for _, attr := range entry.Attributes {
			log.Printf("    %s: %v", attr.Name, attr.Values)
		}
	}
}

func listAllGroups() {
	filter := "(objectClass=groupOfNames)" // Common objectClass for groups
	attributes := []string{"dn", "cn", "member"}
	sr, err := searchEntries(baseDN, filter, attributes)
	if err != nil {
		log.Printf("Error listing groups: %v", err)
		return
	}

	log.Printf("Found %d groups:", len(sr.Entries))
	for _, entry := range sr.Entries {
		log.Printf("  DN: %s, CN: %s", entry.DN, entry.GetAttributeValue("cn"))
		for _, member := range entry.GetAttributeValues("member") {
			log.Printf("    Member: %s", member)
		}
	}
}

func addEntry(dn string, attributes []ldap.Attribute) error {
	if l == nil {
		return fmt.Errorf("not connected to LDAP server")
	}

	addRequest := ldap.NewAddRequest(dn, nil) // Controls can be nil
	for _, attr := range attributes {
		addRequest.Attribute(attr.Type, attr.Vals)
	}

	err := l.Add(addRequest)
	if err != nil {
		return fmt.Errorf("failed to add entry %s: %w", dn, err)
	}
	log.Printf("Successfully added entry: %s", dn)
	return nil
}

// Example Usage of Add:
func addNewUser() {
	newUserDN := "uid=newuser,ou=users," + baseDN // Adjust ou=users as per your DIT
	attrs := []ldap.Attribute{
		{Type: "objectClass", Vals: []string{"top", "person", "organizationalPerson", "inetOrgPerson"}},
		{Type: "uid", Vals: []string{"newuser"}},
		{Type: "cn", Vals: []string{"New User"}},
		{Type: "sn", Vals: []string{"User"}},
		{Type: "givenName", Vals: []string{"New"}},
		{Type: "mail", Vals: []string{"newuser@example.com"}},
		{Type: "userPassword", Vals: []string{"{SSHA}somehashedpassword"}}, // Use a hashed password
	}
	if err := addEntry(newUserDN, attrs); err != nil {
		log.Printf("Error adding new user: %v", err)
	}
}

func modifyEntry(dn string, changes []ldap.Change) error {
	if l == nil {
		return fmt.Errorf("not connected to LDAP server")
	}

	modifyRequest := ldap.NewModifyRequest(dn, nil) // Controls can be nil
	modifyRequest.Changes = changes

	err := l.Modify(modifyRequest)
	if err != nil {
		return fmt.Errorf("failed to modify entry %s: %w", dn, err)
	}
	log.Printf("Successfully modified entry: %s", dn)
	return nil
}

// Example Usage of Modify:
func updateUserEmail(userDN, newEmail string) {
	changes := []ldap.Change{
		{
			Operation: ldap.ReplaceAttribute, // or ldap.AddAttribute if it might not exist
			Modification: ldap.PartialAttribute{
				Type: "mail",
				Vals: []string{newEmail},
			},
		},
	}
	if err := modifyEntry(userDN, changes); err != nil {
		log.Printf("Error updating email for %s: %v", userDN, err)
	}
}

func addUserToGroup(userDN, groupDN string) {
	changes := []ldap.Change{
		{
			Operation: ldap.AddAttribute,
			Modification: ldap.PartialAttribute{
				Type: "member", // For groupOfNames, 'member' attribute holds member DNs
				Vals: []string{userDN},
			},
		},
	}
	if err := modifyEntry(groupDN, changes); err != nil {
		log.Printf("Error adding user %s to group %s: %v", userDN, groupDN, err)
	}
}

func removeUserFromGroup(userDN, groupDN string) {
	changes := []ldap.Change{
		{
			Operation: ldap.DeleteAttribute,
			Modification: ldap.PartialAttribute{
				Type: "member",
				Vals: []string{userDN}, // Specify the value to delete
			},
		},
	}
	if err := modifyEntry(groupDN, changes); err != nil {
		log.Printf("Error removing user %s from group %s: %v", userDN, groupDN, err)
	}
}

func deleteEntry(dn string) error {
	if l == nil {
		return fmt.Errorf("not connected to LDAP server")
	}

	delRequest := ldap.NewDelRequest(dn, nil) // Controls can be nil
	err := l.Del(delRequest)
	if err != nil {
		return fmt.Errorf("failed to delete entry %s: %w", dn, err)
	}
	log.Printf("Successfully deleted entry: %s", dn)
	return nil
}

// Example Usage of Delete:
func removeUser(userDN string) {
	if err := deleteEntry(userDN); err != nil {
		log.Printf("Error deleting user %s: %v", userDN, err)
	}
}

func main() {
	// 1. Connect
	if err := connect(); err != nil {
		log.Fatalf("Initial connection failed: %v", err)
	}
	defer closeConnection()

	// 2. Bind (Authenticate) - Essential for write operations
	if err := bindUser(adminDN, adminPassword); err != nil {
		log.Printf("Admin bind failed: %v. Some operations might fail.", err)
		// Decide if you want to proceed with anonymous access or terminate
		// For this example, we'll try to proceed, but write operations will likely fail.
	}

	// --- Example Operations ---

	log.Println("\n--- Searching for a user 'testuser' (example) ---")
	findUserByUID("testuser") // Assuming 'testuser' might exist

	log.Println("\n--- Listing all groups ---")
	listAllGroups()

	// Example: Adding a new user (ensure admin is bound successfully for this)
	// log.Println("\n--- Attempting to add a new user ---")
	// addNewUser() // This would require `ou=users` to exist under your baseDN

	// Example: Updating an existing user's email
	// Make sure user "uid=existinguser,ou=users,dc=example,dc=org" exists
	// log.Println("\n--- Attempting to update user email ---")
	// updateUserEmail("uid=existinguser,ou=users,"+baseDN, "updated.existinguser@example.com")

	// Example: Add user to group
	// Make sure user and group exist
	// log.Println("\n--- Attempting to add user to group ---")
	// addUserToGroup("uid=newuser,ou=users,"+baseDN, "cn=mygroup,ou=groups,"+baseDN)

	// Example: Deleting a user (use with caution!)
	// log.Println("\n--- Attempting to delete a user ---")
	// removeUser("uid=userToDelete,ou=users,"+baseDN)

	log.Println("\nLDAP operations demonstration finished.")
}

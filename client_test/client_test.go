package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.

	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/google/uuid"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	// var doris *client.User
	// var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	// dorisFile := "dorisFile.txt"
	// eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			// userlib.DebugMsg("User: %v", (*alice).FileInfo)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			// userlib.DebugMsg("User: %v", (*alice).FileInfo)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			// userlib.DebugMsg("User: %v", (*alice).FileInfo)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			david, err := client.InitUser("david", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			invite, err = alice.CreateInvitation(aliceFile, "david")
			Expect(err).To(BeNil())
			err = david.AcceptInvitation("alice", invite, "david.txt")
			Expect(err).To(BeNil())
			userlib.DebugMsg("Checking that you cannot invite nonexistent users")
			_, err = alice.CreateInvitation(aliceFile, "nonexistent user")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that David can still view and modify the file")
			err = david.AppendToFile("david.txt", []byte(contentTwo))
			Expect(err).To(BeNil())
			data, err = david.LoadFile("david.txt")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))
		})

		Specify("Security Test: InitUser and GetUser", func() {
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err = client.InitUser("bob", defaultPassword+"extra")
			Expect(err).To(BeNil())

			// var possible_UUIDs [4]userlib.UUID
			// var aliceBytes []byte
			// hex.Encode(aliceBytes, "alice")
			// possible_UUIDs[0] = uuid.FromBytes(json.Marshal("alice"))[0]
			// actually nevermind, the UUID could just be random

			userlib.DebugMsg("Checking that incorrect passwords cannot login")
			_, err = client.GetUser("alice", defaultPassword+"extra")
			Expect(err).ToNot(BeNil())
			_, err = client.GetUser("bob", defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that incorrect usernames cannot login")
			_, err = client.GetUser("alicebob", defaultPassword)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that usernames cannot be registered twice")
			_, err = client.InitUser("alice", "hihi123")
			Expect(err).ToNot(BeNil())

		})

		Specify("Security Test: Invitations and Revocations", func() {
			userlib.DebugMsg("Checking that invitations can be immediately revoked")
			alice, err = client.InitUser("alice", defaultPassword)
			bob, err = client.InitUser("bob", defaultPassword+"1")
			_ = alice.StoreFile("alice.txt", []byte("test test 4te940wehjrtnxdfdlk"))
			var invite uuid.UUID
			invite, err = alice.CreateInvitation("alice.txt", "bob")
			alice.RevokeAccess("alice.txt", "bob")
			err = bob.AcceptInvitation("alice", invite, "bob.txt")
			Expect(err).ToNot(BeNil())
			err = bob.AcceptInvitation("alice", invite, "bob.txt")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that incorrect filenames do not work")
			userlib.DebugMsg("Also checking StoreFile, LoadFile on empty array")
			err = alice.StoreFile(aliceFile, []byte{})
			Expect(err).To(BeNil())
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte{}))
			invite, err = alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that loading early doesn't work")
			_, err = bob.LoadFile(bobFile) // not shared yet
			Expect(err).ToNot(BeNil())
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())
			_, err = bob.LoadFile("alice.txt")
			Expect(err).ToNot(BeNil())
			_, err = alice.LoadFile("bob.txt")
			Expect(err).ToNot(BeNil())
			userlib.DebugMsg("Blank files should work fine even when shared")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte{}))
			err = bob.AppendToFile(bobFile, []byte("hihi9999"))
			Expect(err).To(BeNil())
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("hihi9999")))

			alicePhone, err := client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			aliceLaptop, err := client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			aliceDesktop, err := client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that StoreFile preserves sharing")
			err = alicePhone.StoreFile(aliceFile, []byte("hihi1234"))
			Expect(err).To(BeNil())
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("hihi1234")))
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("hihi1234")))

			userlib.DebugMsg("StoreFile should not undo revocation")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())
			err = aliceLaptop.StoreFile(aliceFile, []byte("hihi12345"))
			Expect(err).To(BeNil())
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("StoreFile and AppendToFile work together")
			err = aliceDesktop.AppendToFile(aliceFile, []byte("678"))
			Expect(err).To(BeNil())
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("hihi12345678")))
		})

		Specify("Integrity Test: Read/Append/Store", func() {
			userlib.DebugMsg("Append should not work on nonexistent file")
			alice, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			err = alice.StoreFile("alice.txt", []byte("hihi100"))
			Expect(err).To(BeNil())
			err = alice.AppendToFile("bob.txt", []byte("00000"))
			Expect(err).ToNot(BeNil())
		})

		Specify("Integrity Test: File Overwrite Behavior", func() {
			alice, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile("file.txt", []byte("Initial content"))
			Expect(err).To(BeNil())
			err = alice.StoreFile("file.txt", []byte("Overwritten content"))
			Expect(err).To(BeNil())
			data, err := alice.LoadFile("file.txt")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("Overwritten content")))
			err = alice.AppendToFile("file.txt", []byte(" appended"))
			Expect(err).To(BeNil())
			data, err = alice.LoadFile("file.txt")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte("Overwritten content appended")))
		})

		Specify("Miscellaneous Tests", func() {
			// Timing
			alice, err := client.InitUser("alice", "password")
			Expect(err).To(BeNil())
			// Helper function to measure bandwidth of a particular operation
			measureBandwidth := func(probe func()) (bandwidth int) {
				before := userlib.DatastoreGetBandwidth()
				probe()
				after := userlib.DatastoreGetBandwidth()
				return after - before
			}

			userlib.DebugMsg("Check AppendToFile does not scale with number of appends")
			err = alice.StoreFile("newFile.txt", []byte("hello"))
			Expect(err).To(BeNil())
			var bandwidths [100]int
			for i := range bandwidths {
				bw := measureBandwidth(func() {
					err = alice.AppendToFile("newFile.txt", []byte("hello"))
					Expect(err).To(BeNil())
				})
				bandwidths[i] = bw
			}
			userlib.DebugMsg("First ten bandwidths: %v", bandwidths[:10])
			userlib.DebugMsg("Last ten bandwidths: %v", bandwidths[len(bandwidths)-10:])
			Expect(bandwidths[0]).Should(Equal(bandwidths[len(bandwidths)-1]))

			// Modifying other fields
			userlib.DebugMsg("Checking AppendToFile does not scale with other variables")
			longName := "veryLongNameAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.txt"
			err = alice.StoreFile(longName, []byte("hello"))
			Expect(err).To(BeNil())
			_, err = client.InitUser("bob", "password")
			Expect(err).To(BeNil())
			alice.CreateInvitation(longName, "bob")
			err = alice.AppendToFile(longName, []byte("Very long string AAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
			Expect(err).To(BeNil())
			bw := measureBandwidth(func() {
				err = alice.AppendToFile("newFile.txt", []byte("hello"))
				Expect(err).To(BeNil())
			})
			Expect(bw).Should(Equal(bandwidths[0]))
		})

		Specify("Revocation propagates down the sharing chain", func() {
			alice, _ := client.InitUser("alice", defaultPassword)
			bob, _ := client.InitUser("bob", defaultPassword)
			charlie, _ := client.InitUser("charlie", defaultPassword)
			david, _ := client.InitUser("david", defaultPassword)

			alice.StoreFile("a.txt", []byte("chain test"))
			inviteB, _ := alice.CreateInvitation("a.txt", "bob")
			bob.AcceptInvitation("alice", inviteB, "b.txt")

			inviteC, _ := bob.CreateInvitation("b.txt", "charlie")
			charlie.AcceptInvitation("bob", inviteC, "c.txt")

			inviteD, _ := charlie.CreateInvitation("c.txt", "david")
			david.AcceptInvitation("charlie", inviteD, "d.txt")

			alice.RevokeAccess("a.txt", "bob")
			_, err := bob.LoadFile("b.txt")
			Expect(err).ToNot(BeNil())

			_, err = charlie.LoadFile("c.txt")
			Expect(err).ToNot(BeNil())

			_, err = david.LoadFile("d.txt")
			Expect(err).ToNot(BeNil())
		})

		// Specify("Cannot accept the same invitation twice", func() {
		// 	alice, _ := client.InitUser("alice", defaultPassword)
		// 	bob, _ := client.InitUser("bob", defaultPassword)
		// 	alice.StoreFile("file.txt", []byte("secret"))

		// 	invite, _ := alice.CreateInvitation("file.txt", "bob")
		// 	err := bob.AcceptInvitation("alice", invite, "shared.txt")
		// 	Expect(err).To(BeNil())

		// 	err = bob.AcceptInvitation("alice", invite, "shared2.txt")
		// 	Expect(err).ToNot(BeNil())
		// }) // undefined behavior
		Specify("Cannot accept invitation to overwrite existing file", func() {
			alice, _ := client.InitUser("alice", defaultPassword)
			bob, _ := client.InitUser("bob", defaultPassword)
			alice.StoreFile("alice.txt", []byte("original"))

			invite, _ := alice.CreateInvitation("alice.txt", "bob")
			bob.StoreFile("bob.txt", []byte("conflict"))
			err := bob.AcceptInvitation("alice", invite, "bob.txt")
			Expect(err).ToNot(BeNil())
		})

		Specify("Tampered invitation results in error", func() {
			alice, _ := client.InitUser("alice", defaultPassword)
			bob, _ := client.InitUser("bob", defaultPassword)
			alice.StoreFile("a.txt", []byte("hi"))

			invite, _ := alice.CreateInvitation("a.txt", "bob")
			ds := userlib.DatastoreGetMap()
			ds[invite][0] ^= 0xFF

			err := bob.AcceptInvitation("alice", invite, "b.txt")
			Expect(err).ToNot(BeNil())
		})
		Specify("Revoked user cannot StoreFile or CreateInvitation", func() {
			alice, _ := client.InitUser("alice", defaultPassword)
			bob, _ := client.InitUser("bob", defaultPassword)
			alice.StoreFile("file.txt", []byte("abc"))

			invite, _ := alice.CreateInvitation("file.txt", "bob")
			bob.AcceptInvitation("alice", invite, "bob.txt")
			alice.RevokeAccess("file.txt", "bob")

			err := bob.StoreFile("bob.txt", []byte("try write"))
			Expect(err).ToNot(BeNil())

			_, err = bob.CreateInvitation("bob.txt", "charlie")
			Expect(err).ToNot(BeNil())
		})
		Specify("Appending zero bytes does not scale bandwidth", func() {
			alice, _ := client.InitUser("alice", defaultPassword)
			alice.StoreFile("file.txt", []byte("data"))

			bwFirst := userlib.DatastoreGetBandwidth()
			alice.AppendToFile("file.txt", []byte(""))
			bwSecond := userlib.DatastoreGetBandwidth()
			Expect(bwSecond - bwFirst).To(BeNumerically("<", 3000))
		})
		Specify("Non-owner cannot revoke access", func() {
			alice, _ := client.InitUser("alice", defaultPassword)
			bob, _ := client.InitUser("bob", defaultPassword)
			charlie, _ := client.InitUser("charlie", defaultPassword)

			alice.StoreFile("a.txt", []byte("nested"))
			invite, _ := alice.CreateInvitation("a.txt", "bob")
			bob.AcceptInvitation("alice", invite, "b.txt")

			invite, _ = bob.CreateInvitation("b.txt", "charlie")
			charlie.AcceptInvitation("bob", invite, "c.txt")

			err := bob.RevokeAccess("b.txt", "charlie") // Undefined behavior but should be safely handled
			Expect(err).ToNot(BeNil())
		})
		Specify("Edge Case: Revoke before Accept prevents access", func() {
			alice, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err := client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile("secret.txt", []byte("top secret"))
			Expect(err).To(BeNil())

			inv, err := alice.CreateInvitation("secret.txt", "bob")
			Expect(err).To(BeNil())

			err = alice.RevokeAccess("secret.txt", "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", inv, "bob_secret.txt")
			Expect(err).ToNot(BeNil())

			_, err = bob.LoadFile("bob_secret.txt")
			Expect(err).ToNot(BeNil())
		})
		Specify("Security Test: Tampering with invitation UUID should fail", func() {
			alice, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			bob, err := client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.StoreFile("file.txt", []byte("do not share"))
			Expect(err).To(BeNil())

			invite, err := alice.CreateInvitation("file.txt", "bob")
			Expect(err).To(BeNil())

			userlib.DatastoreDelete(invite)
			err = bob.AcceptInvitation("alice", invite, "file_for_bob.txt")
			Expect(err).ToNot(BeNil())
		})
	})
})

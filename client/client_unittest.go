package client

///////////////////////////////////////////////////
//                                               //
// Everything in this file will NOT be graded!!! //
//                                               //
///////////////////////////////////////////////////

// In this unit tests file, you can write white-box unit tests on your implementation.
// These are different from the black-box integration tests in client_test.go,
// because in this unit tests file, you can use details specific to your implementation.

// For example, in this unit tests file, you can access struct fields and helper methods
// that you defined, but in the integration tests (client_test.go), you can only access
// the 8 functions (StoreFile, LoadFile, etc.) that are common to all implementations.

// In this unit tests file, you can write InitUser where you would write client.InitUser in the
// integration tests (client_test.go). In other words, the "client." in front is no longer needed.

import (
	"testing"

	userlib "github.com/cs161-staff/project2-userlib"

	_ "encoding/hex"

	_ "errors"

	. "github.com/onsi/ginkgo/v2"

	. "github.com/onsi/gomega"

	_ "strconv"

	_ "strings"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Unit Tests")
}

// func (userdata *User) DeleteAndTestLoad(filename string, location uuid.UUID) {
// 	obj, ok := userlib.DatastoreGet(location)
// 	Expect(ok).Should(Equal(true))
// 	userlib.DatastoreDelete(location)
// 	_, err := userdata.LoadFile(filename)
// 	Expect(err).ToNot(BeNil())
// 	userlib.DatastoreSet(location, obj)
// }

var _ = Describe("Client Unit Tests", func() {

	BeforeEach(func() {
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Unit Tests", func() {
		Specify("Basic Test: Check that the Username field is set for a new user", func() {
			userlib.DebugMsg("Initializing user Alice.")
			// Note: In the integration tests (client_test.go) this would need to
			// be client.InitUser, but here (client_unittests.go) you can write InitUser.
			alice, err := InitUser("alice", "password")
			Expect(err).To(BeNil())

			// Note: You can access the Username field of the User struct here.
			// But in the integration tests (client_test.go), you cannot access
			// struct fields because not all implementations will have a username field.
			Expect(alice.Username).To(Equal("alice"))
		})

		Specify("Datastore Adversary Test: Deletion Tests", func() {
			alice, err := InitUser("alice", "password")
			Expect(err).To(BeNil())
			UUID, _ := UsernameToUUID("alice")
			_, err = GetUser("alice", "password1")
			Expect(err).ToNot(BeNil())
			_, err = InitUser("alice", "password1")
			Expect(err).ToNot(BeNil()) // same username shouldn't be OK
			alice1, err := InitUser("alice1", "password")
			Expect(err).To(BeNil()) // same password should be fine
			UUID1, _ := UsernameToUUID("alice1")
			data, ok := userlib.DatastoreGet(UUID1)
			Expect(ok).Should(Equal(true))
			userlib.DatastoreSet(UUID, data)
			_, err = GetUser("alice", "password")
			Expect(err).ToNot(BeNil())
			userlib.DebugMsg("%s replacement test %s", alice.Username, alice1.Username)

			// userlib.DebugMsg("Deleting parts of file should result in err")
			// err = alice1.StoreFile("alice.txt", []byte("hello"))
			// Expect(err).To(BeNil())
			// byteLocation := alice1.FileInfo["alice.txt"].LocationOrig
			// markerUUID, err := uuid.FromBytes(AddOneToByteArr(byteLocation))
			// Expect(err).To(BeNil())
			// UUIDplustwo, err := uuid.FromBytes(AddOneToByteArr(AddOneToByteArr(byteLocation)))
			// Expect(err).To(BeNil())
			// alice.DeleteAndTestLoad("alice.txt", alice1.FileInfo["alice.txt"].Location)
			// alice.DeleteAndTestLoad("alice.txt", markerUUID)
			// alice.DeleteAndTestLoad("alice.txt", UUIDplustwo)
		})

		Specify("Revoked User Adversary Tests", func() {
			alice, err := InitUser("alice", "password")
			Expect(err).To(BeNil())
			bob, err := InitUser("bob", "password")
			Expect(err).To(BeNil())
			err = alice.StoreFile("alice.txt", []byte("hi"))
			Expect(err).To(BeNil())
			ptr, err := alice.CreateInvitation("alice.txt", "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", ptr, "bob.txt")
			Expect(err).To(BeNil())
			err = alice.RevokeAccess("alice.txt", "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob tries everything to get back the file")
			oldKey := bob.FileInfo["bob.txt"].FileKey
			location := bob.FileInfo["bob.txt"].Location
			_, err = ReceiveSymObject[File](oldKey, location)
			Expect(err).ToNot(BeNil())
			// testLocFile, err := uuid.FromBytes(AddOneToByteArr(bob.FileInfo["bob.txt"].LocationOrig))
			err = SendSymObject(oldKey, location, bob.FileInfo["bob.txt"])
			Expect(err).To(BeNil())
			_, err = alice.LoadFile("alice.txt")
			Expect(err).To(BeNil())
		})
	})
})

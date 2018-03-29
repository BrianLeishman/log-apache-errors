package main

import (
	"database/sql"
	"flag"
	"fmt"
	"html"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strconv"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/marcsauter/single"
)

type logEntry struct {
	message string
	added   string
	ip      string
}

var db *sql.DB
var insertLogQuery, insertNotificationsQuery *sql.Stmt
var r = regexp.MustCompile(`(?m)^\[(.+?)\] \[(.+?)\] \[(.+?)\] \[client (.+?):[0-9]+\] (.+?) (.+?)$`)
var hostname string

func logError(description string, meta string, added string, ipPTr *string) {
	_, err := insertLogQuery.Exec("<pre>"+html.EscapeString(description)+"</pre>", hostname+"\n"+meta, added, ipPTr)
	if err != nil {
		panic(err) //rip
	}

	_, err = insertNotificationsQuery.Exec(description)
	if err != nil {
		panic(err) //rip
	}
}

func handleErr(err error) {
	if err != nil {
		if insertLogQuery == nil {
			panic(err) //rip
		}

		logError(err.Error(), "log-apache-errors", time.Now().Format("2006-01-02 15:04:05.000000"), nil)
		log.Fatal(err)
	}
}

func main() {

	s := single.New("log-apache-errors")
	if err := s.CheckLock(); err != nil && err == single.ErrAlreadyRunning {
		log.Fatal("another instance of the app is already running, exiting")
	} else if err != nil {
		// Another error occurred, might be worth handling it as well
		log.Fatalf("failed to acquire exclusive app lock: %v", err)
	}
	defer s.TryUnlock()

	usernamePtr := flag.String("u", "root", "your MySQL username")
	passwordPtr := flag.String("p", "", "your MySQL password")
	hostPtr := flag.String("h", "localhost", "your MySQL host")
	portPtr := flag.Int("P", 3306, "your MySQL port")
	databasePtr := flag.String("d", "", "your MySQL database (optional)")

	filePtr := flag.String("e", "/var/log/apache2/error.log", "the path to the error log file")

	flag.Parse()

	if *passwordPtr == "" {
		panic("your MySQL password is required (-p)")
	}

	db, err := sql.Open("mysql", *usernamePtr+":"+*passwordPtr+"@tcp("+*hostPtr+":"+strconv.Itoa(*portPtr)+")/"+*databasePtr+"?charset=utf8mb4&collation=utf8mb4_unicode_ci")
	handleErr(err)
	defer db.Close()

	insertLogQuery, err = db.Prepare("insert into`log`(`Description`,`Meta`,`DateTimeAdded`,`IP`,`Level`)values(?,?,?,?,3);")
	handleErr(err)

	insertNotificationsQuery, err = db.Prepare("insert into`notifications`(`NotificationID`,`ToUserID`,`Description`,`Link`,`Icon`,`DateTimeAdded`)" +
		"select uuid(),`users`.`UserID`,?,'/log.php','warning',now()" +
		"from`users`" +
		"join`userpermissions`using(`UserID`)" +
		"join`permissions`on`permissions`.`PermissionID`=`userpermissions`.`PermissionID`" +
		"and`permissions`.`Name`='Development'" +
		"and`users`.`Deleted`=0;")
	handleErr(err)

	hostname, err = os.Hostname()
	handleErr(err)

	for {
		b, err := ioutil.ReadFile(*filePtr)
		handleErr(err)

		err = os.Truncate(*filePtr, 0)
		handleErr(err)

		s := string(b)

		matches := r.FindAllStringSubmatch(s, -1)
		logEntries := []logEntry{}
		currentLogEntry := -1

		for _, m := range matches {
			message := m[6]
			if len(message) == 0 {
				continue
			}

			t, err := time.Parse("Mon Jan _2 15:04:05.000000 2006", m[1])
			handleErr(err)

			if (message[0] != ' ' && message[0:12] != "Stack trace:") || currentLogEntry == -1 {
				currentLogEntry++
				logEntries = append(logEntries, logEntry{message: message, added: t.Format("2006-01-02 15:04:05.000000"), ip: m[4]})
			} else {
				logEntries[currentLogEntry].message += "\n" + message
			}
		}

		for _, l := range logEntries {

			fmt.Println(l.message, l.added, l.ip, "\n")
			logError(l.message, *filePtr, l.added, &l.ip)

		}

		time.Sleep(20 * time.Millisecond)
	}

}

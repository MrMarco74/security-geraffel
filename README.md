# security-geraffel
Security Geraffel - Everything around security geraffel and some things from me

---

After a year of weekly security foo posts, the collection of tools I mentioned, has grown to over 100.
To get a better overview, I've build a small sqlite database, which will be available soon for you all on github.

I will update it every time I publish a new security fuu post.

Here are some technical information of the sqlite database for you:

<pre><code>CREATE TABLE "security_tools" (
	`tool_id`	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
	`description`	TEXT,
	`category`	TEXT,
	`name`	TEXT,
	`source`	TEXT,
	`url`	TEXT,
	`postdate`	TEXT,
	`updated`	TEXT,
	`post_type`	TEXT
)</code></pre>

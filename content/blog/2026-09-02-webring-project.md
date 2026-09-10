+++
title = "Webring Project"
description = "A novel project for the new Java Spring stack: webrings!"
date = 2026-09-02
+++

Taking CS at Del Norte means you'll probably have a personal website at some point, hence the hundreds of student websites deployed over the years. There is, however, one particular gripe I have with the current system: it's really inconvenient to find other people's websites.

Wouldn't it be nice to have a network or platform to easily traverse classmates' websites? Theoretically, it could help build a sense of community within the CS enclave of DNHS and maybe some reminiscence of the old Internet.

There's a relatively simple way to do this, and has been tried and tested for decades. It has since then lost its novelty, but the rising IndieWeb has picked the practice back up. What I'm referring to is the humble _webring_.

Webrings, in the simplest sense, link websites together through... links. The idea is that some websites within a network link to each other, you eventually form a ring which connects all the websites one way or another:

![ring of websites](/images/webring.png)

There can also be a webring administrator who operates a central server which aggregates all of the websites and, alternatively, offers features like status checks, random routing, etc. Additionally, the presence of a central admin provides resilience to the network, so one website going down doesn't break the continuity of the ring.


## Roadmap

I won't really dwell on the technical implementations in depth, but there's a few features I want:

- **Interactive network graphs**, which supposedly indicate links between sites that don't pass through the main server. Think of something like a network visualization of badge wall connections.
- **Registry filters**, which show sites by year (course level like CSA, CSH, etc.).
- **Service trackers**, which record the basic accessibility of a site.


## Example

I was mainly inspired by a [NixOS webring](https://nixwebr.ing/), which pointed to some pretty cool websites and ran as a tiny Rust server. Of course, I'd actually be writing it in Java to integrate with Spring (don't worry!).

---

## Lombok Setup

I've never worked with Lombok and Java much before, so I had to learn a bit of this. The data flow looks something like this:
```
data model --> JpaRepository --> ApiController
```

First, I defined the data structure:
```java,linenos,name=Webring.java
package com.open.spring.mvc.webring;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

import jakarta.persistence.*;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Webring {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToMany(
        mappedBy = "webring",
        cascade = CascadeType.ALL,
        orphanRemoval = true
    )
    private List<WebringElement> elements = new ArrayList<>();
}
```

We might want multiple webrings in the future (for different interests or some similar demarcation), so I defined the `WebringElement` as `@OneToMany`, which means there can be multiple `WebringElement`s for each `Webring` we create.

Then, we define what a `WebringElement` actually is. We'll want a unique ID for the DB, a username (string), a site URL (string), and position index on the webring (integer):
```java,linenos,file=WebringElement.java
package com.open.spring.mvc.webring;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import jakarta.persistence.*;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
public class WebringElement {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String username;

    @Column(nullable = false)
    private String siteLink;

    @Column(nullable = false)
    private Integer position;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn( name = "webring_id", nullable = false, foreignKey = @ForeignKey(name = "fk_webring_element_webring") )
    @ToStringExclude
    private Webring webring;
}
```

Similarly, we define a `ManyToOne` relation to `Webring`, meaning that there can be multiple `WebringElement`s for one `Webring`. As such, we have a bidirectional relation: Each `Webring` can contain multiple `WebringElement`s, but each `WebringElement` can only belond to one `Webring`.
```
Webring
   │
   ├── WebringElement
   ├── WebringElement
   └── WebringElement

Webring
   │
   ├── WebringElement
   └── WebringElement
```

We use `@JoinColumn()` to generate the `webring_id` on the `webring_element` table:
```
webring_element
┌────┬────────────┬──────────┐
│ id │ webring_id │ username │
├────┼────────────┼──────────┤
│ 10 │     1      │ alice    │
│ 11 │     1      │ bob      │
│ 12 │     2      │ charlie  │
└────┴────────────┴──────────┘
```

Fianlly, we use `@ToStringExclude` to disable some unnecessary features that cost a bit of compute time.

Next, we'll need a `JpaRepository` to handle DB interactions. `JpaRepository` already provides a bunch of built in abstractions which I can just reuse, like `findAll()`, `getById()`, etc. I can write overrides and extensions later, but for the most part I just need a simple declaration of `extends`:
```java,linenos,name=WebringJpaRepository.java
package com.open.spring.mvc.webring;

import org.springframework.data.jpa.repository.JpaRepository;

public interface WebringJpaRepository extends JpaRepository<Webring, Long> {
    // might want List<Webring> findByName(String name);
}
```

Finally, we have the `WebringApiController` that handles the API request:
```java,linenos,WebringApiController.java
package com.open.spring.mvc.webring;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/webring")
public class WebringApiController {
    @Autowired
    private WebringJpaRepository repository;

    // GET members of webring
    @GetMapping("/")
    public ResponseEntity<List<Webring>> getMembers() {
        return new ResponseEntity<>(repository.findAll(), HttpStatus.OK);
    }
}
```

For now, I haven't implemented much at all (just a simple `GET` for all members), which uses the built in `findAll()` method.

## SQLite

The Spring server is already set up to handle table generation, so I just used `sqlite3` to view the db file:
```
sqlite> .schema webring
CREATE TABLE "webring" ("id" integer, primary key ("id"));
sqlite> .schema webring_element
CREATE TABLE "webring_element" ("position" integer not null, "id" integer, "webring_id" bigint not null, "site_link" varchar(255) not null, "username" varchar(255) not null, primary key ("id"));
```

We can also see the table structures:
```
sqlite> PRAGMA table_info(webring);
╭─────┬──────┬─────────┬─────────┬────────────┬────╮
│ cid │ name │  type   │ notnull │ dflt_value │ pk │
╞═════╪══════╪═════════╪═════════╪════════════╪════╡
│   0 │ id   │ INTEGER │       0 │ NULL       │  1 │
╰─────┴──────┴─────────┴─────────┴────────────┴────╯
sqlite> PRAGMA table_info(webring_element);
╭─────┬────────────┬──────────────┬─────────┬────────────┬────╮
│ cid │    name    │     type     │ notnull │ dflt_value │ pk │
╞═════╪════════════╪══════════════╪═════════╪════════════╪════╡
│   0 │ position   │ INTEGER      │       1 │ NULL       │  0 │
│   1 │ id         │ INTEGER      │       0 │ NULL       │  1 │
│   2 │ webring_id │ bigint       │       1 │ NULL       │  0 │
│   3 │ site_link  │ varchar(255) │       1 │ NULL       │  0 │
│   4 │ username   │ varchar(255) │       1 │ NULL       │  0 │
╰─────┴────────────┴──────────────┴─────────┴────────────┴────╯
```

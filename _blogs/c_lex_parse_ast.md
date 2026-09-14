---
layout: blog
title: "Starting the compiler"
date: 2026-09-10
tags: [compiler]
description: "Starting, Lexing, and Parsing"
---

## Intro

I havent posted a blog in a while and lowkey I don't have much time in school left so I better keep at it. I am a slacker. 

Anyways my university's compiler's professor retired on my first semester and he has not been replaced, so I decided to go up to our advanced algorithms/formal languages professor to ask him if we could do an independent study in compilers because there is no fuckin way I am missing out on such an important class. After some nagging (he didn't like the fact I haven't taken formal lang), he decided to do it and is writing his own compiler as well!! The goal is for us to kinda plan to see how his syllabus would look like if he did teach this class in the future. Also he announced that he was doing this and recruited a few people to also do it. Lowkey would of been more fun if it was just me and Dr. Mohan (the goat) vs the world but that's fine.   

Anyways our initial plan was to use the dragon book, learn the concept, and implement it on your compiler but last minute Dr. Mohan thought it would be best to use the `Modern Compiler Implementation in Java` book instead since it gives you a bunch of files and you just have to implement the important parts, which is fine because it 100% saves time. Now because I think C is the chosen language, hate garbage collection, and am a contrarian I decided to use the C counter part of the book. The book is also old as hell, I have to constantly change some things the author does in the given files because it was written using C from like the 90's. 

So the class goal is to do part 1 of the book which goes over the fundamentals of compilation and by the end we should have a working compiler. I will be trying to speedrun this jawn so I can get to part 2 which goes over a bunch of optimization techniques because thats the meat and potatoes (tomatoes?) of compiler theory. I have seen dominator trees in my dreams, they're calling out to me.

Lastly before I start, no I am not using AI. Why would anyone use AI on a "from scratch" project?? You're not gonna make the next `gcc` or `linux` from scatch bruh, the whole fun is that it is `your own` piece of shit implementation. If it is not a piece of shit then it doesn't have any charm (plus it ruins the purpose of learning). But I will say now that I have been slopmaxxing for senior project and (responsively?????) using AI at work so the temptation is there. 

## Chp1: Intro

This chapter was more of a warmup exercise to get us ready, it was pretty fun. They gave us a mini AST and we just had to walk through it and create an interpreter for it. All we had to do was assign variables, handle a stdlib print function, and do math so nothing crazy. My code was nice and clean though and I am proud.

## Chp2: Lexing

This is where we start the compiler, throwing away the first part since we don't need it. This chapter was really fast, all I had to do was write like 30 lines of `lex` and that's it. Somehow I still fucked it up though and I didn't realize until I started testing the parser which made it a funny surprise. I flipped all of the open and close parentheses, brackets, and curly braces into the wrong tokens: 

<img src="/assets/img/IMG_7683.jpeg" width="600" alt="messed up the tokens">

## Chp3: Parsing

God this took so fucking long, very cool once it did work though. So thankfully I don't have to write an LR parser from scratch (though I gave Dr. Mohan the idea to do that for a formal lang assignment), I just have to define the grammar for `yacc` to then build a state machine for me. 

Also the amount of shift/reduce conflicts I would introduce was hilarious. The book said `minimize shift/reduce conflicts and make sure there are no reduce/reduce conflicts`, which to me basically means that shuft/reduce conflicts dont matter and just make sure there are no reduce/reduce conflicts. I think I have like 80+ shift/reduce conflicts I have not touched because I have no reduce/reduce conflicts so hopefully that doesn't bite me in the ass later.

I then implemented some nice error messages and error handling in the parser so that I can print out all of the parsing errors to the screen instead of one by one. All I did was have the lexer `strdup` the current line of source code and store it in a global var when there is a newline, then the parser will just read it if there is an error, and then handle the error to move on:
```
$ ./abs_syn ../../tests/nqueens.tig
../../tests/nqueens.tig:7.14: "    type row := intArray [ N ] of 0"
		syntax error in line 14, near ':='

../../tests/nqueens.tig:13.5: "    ("
		syntax error in line 26, near '('

parse failed
```

When I do the semantic analysis though I will have to add stuff to it in order to then select the line from source based on the token position because it doesn't run hand and hand like how the parser and lexer do.  

## Chp4: Syntax Trees

This chapter was not bad to implement, it did help me find a few issues with my parser as I went along which was nice. The book gives you a bunch of helper functions to build the tree:
```
A_var A_SimpleVar(A_pos pos, S_symbol sym);
A_var A_FieldVar(A_pos pos, A_var var, S_symbol sym);
A_var A_SubscriptVar(A_pos pos, A_var var, A_exp exp);
A_exp A_VarExp(A_pos pos, A_var var);
A_exp A_NilExp(A_pos pos);
...
```

This was very nice, but somewhat alarming because I did my best to adhere to the way that this was designed and did not use everything the EXACT way that it was supposed to. It builds a tree but I wonder how fucked its going to be to parse through it. 

A perfect (and also funny) example of this is how I handled expression nodes: 
```
expseq
    : exp { $$ =  $1; }
    | expseq SEMICOLON exp { $$ = A_SeqExp(EM_tokPos, A_ExpList($1, A_ExpList($3, NULL))); }
    | error SEMICOLON exp { $$ = A_SeqExp(EM_tokPos, A_ExpList(NULL, A_ExpList($3, NULL))); }
    |
    ;
```

Every expression is wrapped inside an `exp node` of type `sequence` which will hold an `explist` node. The head will be the actual expression and then the next node will point to another fabricated `explist` node whose head is the `expseq` type `exp` node that holds a `explist` obj with the REAL next node as a head and so on so forth for however long the expression sequence is. Now I would hope that it's not the intended way to do things, but this was the only way to build the AST without modifying the given files while also keeping the way I set up the whole grammar for the parser. 

And look, the AST builds:
```
$ cat out         
           letExp(
            decList(
             varDec(N,
              intExp(8),
              TRUE),
             decList(
              typeDec(
               nametyList(
                namety(intArray,
                 arrayTy(int)),
                nametyList())),
              decList(
               varDec(row,
                arrayExp(intArray,
                 varExp(
                  simpleVar(N)),
                 intExp(0)),
                TRUE),
               decList(
                varDec(col,
                 arrayExp(intArray,
                  varExp(
                   simpleVar(N)),
                  intExp(0)),
                 TRUE),
...
```


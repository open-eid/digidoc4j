How to start digidoc4j development
===

```bash
git clone --recursive https://github.com/open-eid/digidoc4j.git

cd digidoc4j
ant
```

User stories are described here: 
[https://www.pivotaltracker.com/s/projects/1110130](Pivotal tracker)

To load libraries (including new and updated libraries) without 
performing a complete build: ant load.dependencies

javadoc you can find: [http://open-eid.github.io/digidoc4j/](JavaDoc files)

To run tests:

```bash
ant tests
```

To build and run tests inside IDEA
-----

When using IDEA You only need to install IvyIDEA plugin.

Steps to install IvyIDEA plugin:

1. Preferences -> Plugins
2. Click Browse repositories
3. Search for IvyIDEA
4. Click green Install Plugin button 
5. Repeat steps 3 and 4 to install CheckStyle-IDEA plugin
6. Restart IDEA

Now You need to update Ivy dependencies:

1. Right click on __digidoc4j__
2. Choose __IvyIDEA -> Resolve for 'digidoc4j' module__

Finally setup CheckStyle rules like so:

1. Open __CheckStyle tool window__ 
2. Change rules to: __RIA__
3. Now press run and check that CheckStyle did not find any problems

Now You should be ready to run tests within IDEA.

__Note:__ ClearTSLCache takes long time so please be patient

Instructions for Eclipse users
----

__TODO:__ Will be added soon


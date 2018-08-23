When creating new unit test classes make sure to use **org.digidoc4j.AbstractTest**
as parent class. Always use methods published by this abstract class e.g. when
you would like to create *temporary* file then use **getFileBy(\<extension\>)**
method. NB! you don't have to worry about cleaning afterwards. For junit's *@Before*
and *@After* override *before()* and *after()* methods accordingly. You can create
new methods into parent class when method signatures doesn't  fill your needs
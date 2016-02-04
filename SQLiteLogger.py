#
# SQLite Logger v1.0.1
# Burp Request and Response Logging
# by. abend
#

from burp import IBurpExtender
from burp import ITab
from burp import IHttpListener
from burp import IBurpExtenderCallbacks
from burp import IMessageEditorController
from java.awt import Component;
from java.io import PrintWriter;
from java.util import ArrayList;
from java.util import List;
from java.lang import Class
from java.sql import DriverManager
from javax.swing import JScrollPane;
from javax.swing import JSplitPane;
from javax.swing import JTabbedPane;
from javax.swing import JTable;
from javax.swing import SwingUtilities;
from javax.swing.table import AbstractTableModel;
from threading import Lock
import urlparse
import datetime
from java.lang import Class
from java.sql import DriverManager

# this class is for import sqlite-jdbc.jar
class classPathHacker:
    import java.net.URLClassLoader
    
    def addFile(self, s):
        sysloader = self.java.lang.ClassLoader.getSystemClassLoader()
        sysclass = self.java.net.URLClassLoader
        method = sysclass.getDeclaredMethod("addURL", [self.java.net.URL])
        method.setAccessible(1)
        f = self.java.io.File(s)
        method.invoke(sysloader, [f.toURL()])

class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController, AbstractTableModel, IBurpExtenderCallbacks):
    import java.net.URLClassLoader
    statement = None
    con = None

    def	registerExtenderCallbacks(self, callbacks):
        global statement,con

        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("SQLite Logger")

        # select sqlite jdbc jar file
        c = classPathHacker()
        c.addFile("C:\\sqlite-jdbc-3.8.11.2.jar")

        # database filename.
        jdbc_url = "jdbc:sqlite:database" + str(datetime.date.today()) + ".db"
        driver = "org.sqlite.JDBC"
        Class.forName(driver).newInstance()
        con = DriverManager.getConnection(jdbc_url)

        # create table
        self.sql = "CREATE TABLE if not exists log(host text,path text,method text,request text,response text,time text);"
        statement = con.prepareStatement(self.sql)
        statement.executeUpdate()
        
        self._log = ArrayList()
        self._lock = Lock()

        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)

        logTable = Table(self)
        scrollPane = JScrollPane(logTable)
        self._splitpane.setLeftComponent(scrollPane)

        tabs = JTabbedPane()
        self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)
        tabs.addTab("Request", self._requestViewer.getComponent())
        tabs.addTab("Response", self._responseViewer.getComponent())
        self._splitpane.setRightComponent(tabs)

        callbacks.customizeUiComponent(self._splitpane)
        callbacks.customizeUiComponent(logTable)
        callbacks.customizeUiComponent(scrollPane)
        callbacks.customizeUiComponent(tabs)

        callbacks.addSuiteTab(self)

        callbacks.registerHttpListener(self)
        
        return


    def exitSuite(self,False):
        con.close()
        return

    def getTabCaption(self):
        return "SQLite Logger"


    def getUiComponent(self):
        return self._splitpane


    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        global statement

        # insert into database request,response
        if not messageIsRequest:
            self._lock.acquire()
            row = self._log.size()

            self.reqinfo = self._helpers.analyzeRequest(messageInfo)
            self.parsed = urlparse.urlparse(self.reqinfo.getUrl().toString())

            print "request"
            print self._helpers.bytesToString(messageInfo.getRequest())
            print ""
            print "req header"
            print self._helpers.bytesToString(messageInfo.getResponse()).encode('utf8', 'replace')
            print ""

            self._log.add(LogEntry(toolFlag, self._callbacks.saveBuffersToTempFiles(messageInfo),self.reqinfo.getMethod(), self.parsed.netloc, self.parsed.path))


            self.sql = "INSERT INTO log(host,path,method,request,response,time) VALUES (?,?,?,?,?,?);"
            statement = con.prepareStatement(self.sql)

            statement.setString(1,self.parsed.path)
            statement.setString(2,self.parsed.netloc)
            statement.setString(3,self.reqinfo.getMethod())
            statement.setString(4,self._helpers.bytesToString(messageInfo.getRequest()))
            statement.setString(5,self._helpers.bytesToString(messageInfo.getResponse()))
            statement.setString(6,str(datetime.datetime.today()))
            statement.executeUpdate()

            self.fireTableRowsInserted(row, row)
            self._lock.release()
        return


    def getRowCount(self):
        try:
            return self._log.size()
        except:
            return 0

    def getColumnCount(self):
        return 4

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "Tool"
        if columnIndex == 1:
            return "Method"
        if columnIndex == 2:
            return "Host"
        if columnIndex == 3:
            return "Path"

        return ""


    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex)
        if columnIndex == 0:
            return self._callbacks.getToolName(logEntry._tool)
        if columnIndex == 1:
            return logEntry._method
        if columnIndex == 2:
            return logEntry._host
        if columnIndex == 3:
            return logEntry._path
        return ""


    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService()


    def getRequest(self):
        return self._currentlyDisplayedItem.getRequest()


    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse()


class Table(JTable):

    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)
        return


    def changeSelection(self, row, col, toggle, extend):
        logEntry = self._extender._log.get(row)
        self._extender._requestViewer.setMessage(logEntry._requestResponse.getRequest(), True)
        self._extender._responseViewer.setMessage(logEntry._requestResponse.getResponse(), False)
        self._extender._currentlyDisplayedItem = logEntry._requestResponse
        
        JTable.changeSelection(self, row, col, toggle, extend)
        return


class LogEntry:

    def __init__(self, tool, requestResponse, method, host, path):
        self._tool = tool
        self._requestResponse = requestResponse
        self._method = method
        self._host = host
        self._path = path
        return



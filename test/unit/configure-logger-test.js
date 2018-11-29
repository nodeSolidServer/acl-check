'use strict'

const test = require('tape')
const sinon = require('sinon')
const { log, configureLogger } = require('../../src/acl-check')

test('by default logger is console.log', t => {
  const defaultLogger = console.log
  console.log = sinon.spy()

  log('foo', 'bar', 42)

  t.ok(console.log.calledWith('foo', 'bar', 42), 'should call console.log by default')

  t.end()

  console.log = defaultLogger
})

test('can set custom logger', t => {
  const logger = sinon.stub()
  configureLogger(logger)

  log('foo', 'bar', 42)

  t.ok(logger.calledWith('foo', 'bar', 42), 'should call custom logger')

  t.end()

  configureLogger(null)
})

/**
 * angular-strap
 * @version v2.2.1 - 2015-03-10
 * @link http://mgcrea.github.io/angular-strap
 * @author Olivier Louvignes (olivier@mg-crea.com)
 * @license MIT License, http://www.opensource.org/licenses/MIT
 */
'use strict';

angular.module('mgcrea.ngStrap.popover').run(['$templateCache', function($templateCache) {

  $templateCache.put('popover/popover.tpl.html', '<div cl***REMOVED***="popover"><div cl***REMOVED***="arrow"></div><h3 cl***REMOVED***="popover-title" ng-bind="title" ng-show="title"></h3><div cl***REMOVED***="popover-content" ng-bind="content"></div></div>');

}]);
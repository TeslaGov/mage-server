/**
 * angular-strap
 * @version v2.2.1 - 2015-03-10
 * @link http://mgcrea.github.io/angular-strap
 * @author Olivier Louvignes (olivier@mg-crea.com)
 * @license MIT License, http://www.opensource.org/licenses/MIT
 */
'use strict';

angular.module('mgcrea.ngStrap.aside').run(['$templateCache', function($templateCache) {

  $templateCache.put('aside/aside.tpl.html', '<div cl***REMOVED***="aside" tabindex="-1" role="dialog"><div cl***REMOVED***="aside-dialog"><div cl***REMOVED***="aside-content"><div cl***REMOVED***="aside-header" ng-show="title"><button type="button" cl***REMOVED***="close" ng-click="$hide()">&times;</button><h4 cl***REMOVED***="aside-title" ng-bind="title"></h4></div><div cl***REMOVED***="aside-body" ng-bind="content"></div><div cl***REMOVED***="aside-footer"><button type="button" cl***REMOVED***="btn btn-default" ng-click="$hide()">Close</button></div></div></div></div>');

}]);
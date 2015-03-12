/**
 * angular-strap
 * @version v2.2.1 - 2015-03-10
 * @link http://mgcrea.github.io/angular-strap
 * @author Olivier Louvignes (olivier@mg-crea.com)
 * @license MIT License, http://www.opensource.org/licenses/MIT
 */
'use strict';

angular.module('mgcrea.ngStrap.modal').run(['$templateCache', function($templateCache) {

  $templateCache.put('modal/modal.tpl.html', '<div cl***REMOVED***="modal" tabindex="-1" role="dialog" aria-hidden="true"><div cl***REMOVED***="modal-dialog"><div cl***REMOVED***="modal-content"><div cl***REMOVED***="modal-header" ng-show="title"><button type="button" cl***REMOVED***="close" aria-label="Close" ng-click="$hide()"><span aria-hidden="true">&times;</span></button><h4 cl***REMOVED***="modal-title" ng-bind="title"></h4></div><div cl***REMOVED***="modal-body" ng-bind="content"></div><div cl***REMOVED***="modal-footer"><button type="button" cl***REMOVED***="btn btn-default" ng-click="$hide()">Close</button></div></div></div></div>');

}]);
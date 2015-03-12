/**
 * angular-strap
 * @version v2.2.1 - 2015-03-10
 * @link http://mgcrea.github.io/angular-strap
 * @author Olivier Louvignes (olivier@mg-crea.com)
 * @license MIT License, http://www.opensource.org/licenses/MIT
 */
'use strict';

angular.module('mgcrea.ngStrap.datepicker').run(['$templateCache', function($templateCache) {

  $templateCache.put('datepicker/datepicker.tpl.html', '<div cl***REMOVED***="dropdown-menu datepicker" ng-cl***REMOVED***="\'datepicker-mode-\' + $mode" style="max-width: 320px"><table style="table-layout: fixed; height: 100%; width: 100%"><thead><tr cl***REMOVED***="text-center"><th><button tabindex="-1" type="button" cl***REMOVED***="btn btn-default pull-left" ng-click="$selectPane(-1)"><i cl***REMOVED***="{{$iconLeft}}"></i></button></th><th colspan="{{ rows[0].length - 2 }}"><button tabindex="-1" type="button" cl***REMOVED***="btn btn-default btn-block text-strong" ng-click="$toggleMode()"><strong style="text-transform: capitalize" ng-bind="title"></strong></button></th><th><button tabindex="-1" type="button" cl***REMOVED***="btn btn-default pull-right" ng-click="$selectPane(+1)"><i cl***REMOVED***="{{$iconRight}}"></i></button></th></tr><tr ng-show="showLabels" ng-bind-html="labels"></tr></thead><tbody><tr ng-repeat="(i, row) in rows" height="{{ 100 / rows.length }}%"><td cl***REMOVED***="text-center" ng-repeat="(j, el) in row"><button tabindex="-1" type="button" cl***REMOVED***="btn btn-default" style="width: 100%" ng-cl***REMOVED***="{\'btn-primary\': el.selected, \'btn-info btn-today\': el.isToday && !el.selected}" ng-click="$select(el.date)" ng-disabled="el.disabled"><span ng-cl***REMOVED***="{\'text-muted\': el.muted}" ng-bind="el.label"></span></button></td></tr></tbody></table></div>');

}]);